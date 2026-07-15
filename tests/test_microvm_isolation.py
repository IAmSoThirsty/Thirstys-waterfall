"""
Tests for MicroVM Isolation Module
"""

import unittest
import time
import os
import tempfile
from unittest.mock import patch, MagicMock
from thirstys_waterfall.security.microvm_isolation import (
    MicroVMIsolationManager,
    MicroVMInstance,
    VMBackend,
    VMState,
    IsolationType,
    VMResourceLimits,
    VMNetworkConfig,
    CommunicationChannel,
)


class TestVMResourceLimits(unittest.TestCase):
    """Test VM resource limit configuration"""

    def test_default_limits(self):
        """Test default resource limits"""
        limits = VMResourceLimits()
        self.assertEqual(limits.vcpu_count, 1)
        self.assertEqual(limits.memory_mb, 512)
        self.assertEqual(limits.disk_size_mb, 1024)

    def test_custom_limits(self):
        """Test custom resource limits"""
        limits = VMResourceLimits(vcpu_count=2, memory_mb=1024, disk_size_mb=2048)
        self.assertEqual(limits.vcpu_count, 2)
        self.assertEqual(limits.memory_mb, 1024)
        self.assertEqual(limits.disk_size_mb, 2048)


class TestVMNetworkConfig(unittest.TestCase):
    """Test VM network configuration"""

    def test_isolated_network_default(self):
        """Test that isolated network is default"""
        config = VMNetworkConfig()
        self.assertTrue(config.isolated_network)

    def test_custom_network_config(self):
        """Test custom network configuration"""
        config = VMNetworkConfig(
            tap_device="tap0", ip_address="192.168.100.10", isolated_network=False
        )
        self.assertEqual(config.tap_device, "tap0")
        self.assertEqual(config.ip_address, "192.168.100.10")
        self.assertFalse(config.isolated_network)


class TestCommunicationChannel(unittest.TestCase):
    """Test communication channel"""

    def test_channel_creation(self):
        """Test channel creation"""
        channel = CommunicationChannel("test_vm_123")
        self.assertEqual(channel.vm_id, "test_vm_123")
        self.assertIn("test_vm_123", channel.socket_path)

    def test_custom_socket_path(self):
        """Test custom socket path"""
        channel = CommunicationChannel("test_vm", "/tmp/custom.sock")
        self.assertEqual(channel.socket_path, "/tmp/custom.sock")

    @patch(
        "thirstys_waterfall.security.microvm_isolation.socket.AF_UNIX",
        1,
        create=True,
    )
    @patch("thirstys_waterfall.security.microvm_isolation.socket.socket")
    @patch("thirstys_waterfall.security.microvm_isolation.os.path.exists")
    def test_failed_connection_closes_created_socket(
        self, mock_exists, mock_socket_factory
    ):
        mock_exists.return_value = True
        created_socket = mock_socket_factory.return_value
        created_socket.connect.side_effect = OSError("connection failed")
        channel = CommunicationChannel("test_vm", "/tmp/custom.sock")

        self.assertFalse(channel.connect())

        created_socket.close.assert_called_once_with()
        self.assertIsNone(channel._socket)


class TestMicroVMInstance(unittest.TestCase):
    """Test MicroVM instance"""

    def setUp(self):
        """Set up test VM instance"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.kernel_path = os.path.join(self.temp_dir.name, "vmlinux")
        self.rootfs_path = os.path.join(self.temp_dir.name, "rootfs.ext4")
        with open(self.kernel_path, "wb") as f:
            f.write(b"kernel")
        with open(self.rootfs_path, "wb") as f:
            f.write(b"rootfs")

        self.limits = VMResourceLimits(vcpu_count=1, memory_mb=512)
        self.vm = MicroVMInstance(
            vm_id="test_vm_001",
            backend=VMBackend.QEMU,
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=self.limits,
            kernel_path=self.kernel_path,
            rootfs_path=self.rootfs_path,
        )

    def tearDown(self):
        """Clean up test VM assets"""
        self.temp_dir.cleanup()

    def test_vm_creation(self):
        """Test VM instance creation"""
        self.assertEqual(self.vm.vm_id, "test_vm_001")
        self.assertEqual(self.vm.backend, VMBackend.QEMU)
        self.assertEqual(self.vm.isolation_type, IsolationType.BROWSER_TAB)
        self.assertEqual(self.vm.get_state(), VMState.CREATED)

    def test_initial_state(self):
        """Test initial VM state"""
        self.assertEqual(self.vm.get_state(), VMState.CREATED)
        info = self.vm.get_info()
        self.assertEqual(info["state"], VMState.CREATED.value)
        self.assertEqual(info["vm_id"], "test_vm_001")

    def test_firecracker_command_requires_initialized_config(self):
        vm = MicroVMInstance(
            vm_id="firecracker_config",
            backend=VMBackend.FIRECRACKER,
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=self.limits,
            kernel_path=self.kernel_path,
            rootfs_path=self.rootfs_path,
        )

        with self.assertRaisesRegex(RuntimeError, "configuration file"):
            vm._build_firecracker_command()

    def test_resource_limits_applied(self):
        """Test resource limits are applied"""
        info = self.vm.get_info()
        self.assertEqual(info["resource_limits"]["vcpu_count"], 1)
        self.assertEqual(info["resource_limits"]["memory_mb"], 512)

    def test_isolated_network_default(self):
        """Test isolated network is default"""
        info = self.vm.get_info()
        self.assertTrue(info["network_config"]["isolated"])

    @patch("subprocess.Popen")
    def test_vm_start_attempt(self, mock_popen):
        """Test VM start attempt (mocked)"""
        # Mock process
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        # Mock channel connection
        with patch.object(self.vm._channel, "connect", return_value=True):
            with patch.object(self.vm._channel, "send_message", return_value=True):
                with patch.object(
                    self.vm._channel, "receive_message", return_value={"type": "pong"}
                ):
                    # Start should succeed
                    self.vm.start()

                    # Should have attempted to start
                    self.assertTrue(mock_popen.called)

    def test_vm_state_transitions(self):
        """Test VM state transitions"""
        # Initial state
        self.assertEqual(self.vm.get_state(), VMState.CREATED)

        # Cannot pause when not running
        self.assertFalse(self.vm.pause())

        # Cannot resume when not paused
        self.assertFalse(self.vm.resume())

    def test_missing_boot_assets_fail_closed(self):
        """Test VM start fails closed when boot assets are missing"""
        vm = MicroVMInstance(
            vm_id="missing_assets",
            backend=VMBackend.QEMU,
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=self.limits,
            kernel_path=os.path.join(self.temp_dir.name, "missing-kernel"),
            rootfs_path=os.path.join(self.temp_dir.name, "missing-rootfs"),
        )

        self.assertFalse(vm.start())
        self.assertEqual(vm.get_state(), VMState.ERROR)
        self.assertEqual(
            vm.operation_evidence["boot_assets"]["status"], "unavailable"
        )

    def test_non_isolated_network_requires_backend(self):
        """Test host network setup fails closed without backend evidence"""
        vm = MicroVMInstance(
            vm_id="network_required",
            backend=VMBackend.QEMU,
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=self.limits,
            network_config=VMNetworkConfig(isolated_network=False),
            kernel_path=self.kernel_path,
            rootfs_path=self.rootfs_path,
        )

        self.assertFalse(vm._setup_networking())
        self.assertEqual(
            vm.operation_evidence["network_setup"]["reason"],
            "network_backend_not_configured",
        )

    def test_non_isolated_network_backend_evidence(self):
        """Test host network setup accepts configured backend evidence"""

        class PlatformBackend:
            def setup_networking(self, vm, tap_name):
                return {
                    "status": "applied",
                    "tap_device": tap_name,
                    "backend": "test-net",
                }

        vm = MicroVMInstance(
            vm_id="network_backend",
            backend=VMBackend.QEMU,
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=self.limits,
            network_config=VMNetworkConfig(isolated_network=False),
            kernel_path=self.kernel_path,
            rootfs_path=self.rootfs_path,
            platform_backend=PlatformBackend(),
        )

        self.assertTrue(vm._setup_networking())
        self.assertEqual(vm.operation_evidence["network_setup"]["backend"], "test-net")

    def test_pause_resume_require_control_backend(self):
        """Test pause/resume no longer flip state without backend evidence"""
        self.vm._state = VMState.RUNNING

        self.assertFalse(self.vm.pause())
        self.assertEqual(self.vm.get_state(), VMState.RUNNING)
        self.assertEqual(
            self.vm.operation_evidence["pause"]["reason"],
            "control_backend_not_configured",
        )

    def test_pause_resume_backend_evidence(self):
        """Test pause/resume use configured control backend evidence"""

        class PlatformBackend:
            def pause(self, vm):
                return {"status": "paused", "backend": "test-control"}

            def resume(self, vm):
                return {"status": "running", "backend": "test-control"}

        vm = MicroVMInstance(
            vm_id="control_backend",
            backend=VMBackend.QEMU,
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=self.limits,
            kernel_path=self.kernel_path,
            rootfs_path=self.rootfs_path,
            platform_backend=PlatformBackend(),
        )
        vm._state = VMState.RUNNING

        self.assertTrue(vm.pause())
        self.assertEqual(vm.get_state(), VMState.PAUSED)
        self.assertEqual(vm.operation_evidence["pause"]["backend"], "test-control")
        self.assertTrue(vm.resume())
        self.assertEqual(vm.get_state(), VMState.RUNNING)
        self.assertEqual(vm.operation_evidence["resume"]["backend"], "test-control")

    def test_health_metrics_liveness_evidence(self):
        """Test built-in health path reports liveness-only evidence"""
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        self.vm._process = mock_process
        self.vm._pid = 12345
        self.vm._start_time = time.time()

        self.vm._update_health_metrics()

        self.assertEqual(self.vm.get_health_metrics().health_status, "healthy")
        self.assertEqual(
            self.vm.operation_evidence["health_metrics"]["status"],
            "process_liveness_only",
        )

    def test_health_metrics_backend_evidence(self):
        """Test configured backend can provide concrete health metrics"""

        class PlatformBackend:
            def collect_metrics(self, vm, pid):
                return {
                    "cpu_usage_percent": 12.5,
                    "memory_usage_mb": 64,
                    "health_status": "healthy",
                    "last_health_check": time.time(),
                }

        vm = MicroVMInstance(
            vm_id="metrics_backend",
            backend=VMBackend.QEMU,
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=self.limits,
            kernel_path=self.kernel_path,
            rootfs_path=self.rootfs_path,
            platform_backend=PlatformBackend(),
        )
        vm._process = MagicMock()
        vm._pid = 12345

        vm._update_health_metrics()

        self.assertEqual(vm.get_health_metrics().cpu_usage_percent, 12.5)
        self.assertEqual(vm.get_health_metrics().memory_usage_mb, 64)
        self.assertEqual(
            vm.operation_evidence["health_metrics"]["status"], "collected"
        )


class TestMicroVMIsolationManager(unittest.TestCase):
    """Test MicroVM isolation manager"""

    def setUp(self):
        """Set up test manager"""
        config = {
            "max_vcpus": 8,
            "max_memory_mb": 4096,
            "default_vcpu_count": 1,
            "default_memory_mb": 512,
            "default_backend": "QEMU",
        }
        self.manager = MicroVMIsolationManager(config)

    def test_manager_creation(self):
        """Test manager creation"""
        self.assertIsNotNone(self.manager)
        self.assertEqual(self.manager._max_vcpus, 8)
        self.assertEqual(self.manager._max_memory_mb, 4096)

    def test_manager_start_stop(self):
        """Test manager start and stop"""
        self.manager.start()
        time.sleep(0.1)  # Let threads start

        self.manager.stop()
        # Manager should clean up
        self.assertFalse(self.manager._cleanup_active)

    def test_create_vm(self):
        """Test VM creation"""
        vm_id = self.manager.create_vm(isolation_type=IsolationType.BROWSER_TAB)

        self.assertIsNotNone(vm_id)
        self.assertIn("browser_tab", vm_id)

        # Verify VM exists
        vm = self.manager.get_vm(vm_id)
        self.assertIsNotNone(vm)
        self.assertEqual(vm.isolation_type, IsolationType.BROWSER_TAB)

    def test_create_multiple_vms(self):
        """Test creating multiple VMs"""
        vm1 = self.manager.create_vm(IsolationType.BROWSER_TAB)
        vm2 = self.manager.create_vm(IsolationType.EXTENSION)
        vm3 = self.manager.create_vm(IsolationType.SESSION)

        self.assertIsNotNone(vm1)
        self.assertIsNotNone(vm2)
        self.assertIsNotNone(vm3)

        # All should be different
        self.assertNotEqual(vm1, vm2)
        self.assertNotEqual(vm2, vm3)
        self.assertNotEqual(vm1, vm3)

    def test_resource_limits(self):
        """Test resource limit enforcement"""
        # Create VMs until resources exhausted
        vms = []

        for i in range(10):
            vm_id = self.manager.create_vm(
                isolation_type=IsolationType.BROWSER_TAB,
                resource_limits=VMResourceLimits(vcpu_count=1, memory_mb=512),
            )
            if vm_id:
                vms.append(vm_id)
            else:
                break

        # Should have hit resource limit
        self.assertLessEqual(len(vms), 8)  # max_vcpus = 8

    def test_resource_tracking(self):
        """Test resource usage tracking"""
        self.manager.create_vm(
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=VMResourceLimits(vcpu_count=2, memory_mb=1024),
        )

        usage = self.manager.get_resource_usage()
        self.assertEqual(usage["vcpus_allocated"], 2)
        self.assertEqual(usage["memory_allocated_mb"], 1024)
        self.assertEqual(usage["total_vms"], 1)

    def test_list_vms(self):
        """Test listing VMs"""
        # Create different types
        tab_vm = self.manager.create_vm(IsolationType.BROWSER_TAB)
        self.manager.create_vm(IsolationType.EXTENSION)

        # List all
        all_vms = self.manager.list_vms()
        self.assertEqual(len(all_vms), 2)

        # List by type
        tab_vms = self.manager.list_vms(isolation_type=IsolationType.BROWSER_TAB)
        self.assertEqual(len(tab_vms), 1)
        self.assertIn(tab_vm, tab_vms)

    def test_destroy_vm(self):
        """Test VM destruction"""
        vm_id = self.manager.create_vm(IsolationType.BROWSER_TAB)
        self.assertIsNotNone(vm_id)

        # Destroy VM
        result = self.manager.destroy_vm(vm_id)
        self.assertTrue(result)

        # VM should no longer exist
        vm = self.manager.get_vm(vm_id)
        self.assertIsNone(vm)

        # Resources should be freed
        usage = self.manager.get_resource_usage()
        self.assertEqual(usage["total_vms"], 0)

    def test_destroy_all_vms(self):
        """Test destroying all VMs"""
        # Create multiple VMs
        self.manager.create_vm(IsolationType.BROWSER_TAB)
        self.manager.create_vm(IsolationType.EXTENSION)
        self.manager.create_vm(IsolationType.SESSION)

        # Verify created
        self.assertEqual(len(self.manager.list_vms()), 3)

        # Destroy all
        self.manager.destroy_all_vms()

        # All should be gone
        self.assertEqual(len(self.manager.list_vms()), 0)

    def test_get_vm_info(self):
        """Test getting VM info"""
        vm_id = self.manager.create_vm(
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=VMResourceLimits(vcpu_count=2, memory_mb=1024),
        )

        info = self.manager.get_vm_info(vm_id)
        self.assertIsNotNone(info)
        self.assertEqual(info["vm_id"], vm_id)
        self.assertEqual(info["isolation_type"], IsolationType.BROWSER_TAB.value)
        self.assertEqual(info["resource_limits"]["vcpu_count"], 2)
        self.assertEqual(info["resource_limits"]["memory_mb"], 1024)

    def test_get_all_vms_info(self):
        """Test getting all VMs info"""
        vm1 = self.manager.create_vm(IsolationType.BROWSER_TAB)
        vm2 = self.manager.create_vm(IsolationType.EXTENSION)

        all_info = self.manager.get_all_vms_info()
        self.assertEqual(len(all_info), 2)
        self.assertIn(vm1, all_info)
        self.assertIn(vm2, all_info)

    def test_health_status(self):
        """Test health status"""
        self.manager.create_vm(IsolationType.BROWSER_TAB)
        self.manager.create_vm(IsolationType.EXTENSION)

        health = self.manager.get_health_status()
        self.assertEqual(health["total_vms"], 2)
        self.assertIn("healthy_vms", health)
        self.assertIn("unhealthy_vms", health)
        self.assertIn("resource_usage", health)

    def test_vms_by_type_count(self):
        """Test VM counting by type"""
        self.manager.create_vm(IsolationType.BROWSER_TAB)
        self.manager.create_vm(IsolationType.BROWSER_TAB)
        self.manager.create_vm(IsolationType.EXTENSION)

        usage = self.manager.get_resource_usage()
        by_type = usage["vms_by_type"]

        self.assertEqual(by_type["browser_tab"], 2)
        self.assertEqual(by_type["extension"], 1)

    def test_custom_vm_id(self):
        """Test creating VM with custom ID"""
        custom_id = "my_custom_vm_001"
        vm_id = self.manager.create_vm(
            isolation_type=IsolationType.SESSION, vm_id=custom_id
        )

        self.assertEqual(vm_id, custom_id)

        # Should not be able to create duplicate
        vm_id2 = self.manager.create_vm(
            isolation_type=IsolationType.SESSION, vm_id=custom_id
        )
        self.assertIsNone(vm_id2)


class TestIsolationTypes(unittest.TestCase):
    """Test isolation type enumerations"""

    def test_isolation_types_exist(self):
        """Test that all isolation types are defined"""
        self.assertTrue(hasattr(IsolationType, "BROWSER_TAB"))
        self.assertTrue(hasattr(IsolationType, "EXTENSION"))
        self.assertTrue(hasattr(IsolationType, "SESSION"))
        self.assertTrue(hasattr(IsolationType, "PLUGIN"))

    def test_isolation_type_values(self):
        """Test isolation type values"""
        self.assertEqual(IsolationType.BROWSER_TAB.value, "browser_tab")
        self.assertEqual(IsolationType.EXTENSION.value, "extension")
        self.assertEqual(IsolationType.SESSION.value, "session")
        self.assertEqual(IsolationType.PLUGIN.value, "plugin")


class TestVMBackends(unittest.TestCase):
    """Test VM backend enumerations"""

    def test_backends_exist(self):
        """Test that all backends are defined"""
        self.assertTrue(hasattr(VMBackend, "FIRECRACKER"))
        self.assertTrue(hasattr(VMBackend, "QEMU"))
        self.assertTrue(hasattr(VMBackend, "CLOUD_HYPERVISOR"))

    def test_backend_values(self):
        """Test backend values"""
        self.assertEqual(VMBackend.FIRECRACKER.value, "firecracker")
        self.assertEqual(VMBackend.QEMU.value, "qemu")
        self.assertEqual(VMBackend.CLOUD_HYPERVISOR.value, "cloud-hypervisor")


class TestVMStates(unittest.TestCase):
    """Test VM state enumerations"""

    def test_states_exist(self):
        """Test that all states are defined"""
        states = [
            "CREATED",
            "STARTING",
            "RUNNING",
            "PAUSED",
            "STOPPING",
            "STOPPED",
            "ERROR",
            "DESTROYED",
        ]
        for state in states:
            self.assertTrue(hasattr(VMState, state))


class TestEvidenceGatedFeatures(unittest.TestCase):
    """Test evidence-gated features"""

    def setUp(self):
        """Set up manager"""
        self.manager = MicroVMIsolationManager()

    def test_thread_safety(self):
        """Test thread-safe operations"""
        import threading

        results = []

        def create_vm():
            vm_id = self.manager.create_vm(IsolationType.BROWSER_TAB)
            results.append(vm_id)

        # Create VMs from multiple threads
        threads = [threading.Thread(target=create_vm) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed
        self.assertEqual(len(results), 5)
        # All should be unique
        self.assertEqual(len(set(results)), 5)

    def test_resource_allocation_tracking(self):
        """Test accurate resource tracking"""
        initial_usage = self.manager.get_resource_usage()
        initial_vcpus = initial_usage["vcpus_allocated"]
        initial_memory = initial_usage["memory_allocated_mb"]

        # Create VM
        vm_id = self.manager.create_vm(
            isolation_type=IsolationType.BROWSER_TAB,
            resource_limits=VMResourceLimits(vcpu_count=2, memory_mb=1024),
        )

        # Check allocation
        usage = self.manager.get_resource_usage()
        self.assertEqual(usage["vcpus_allocated"], initial_vcpus + 2)
        self.assertEqual(usage["memory_allocated_mb"], initial_memory + 1024)

        # Destroy VM
        self.manager.destroy_vm(vm_id)

        # Check deallocation
        usage = self.manager.get_resource_usage()
        self.assertEqual(usage["vcpus_allocated"], initial_vcpus)
        self.assertEqual(usage["memory_allocated_mb"], initial_memory)

    def test_lifecycle_management(self):
        """Test complete VM lifecycle"""
        # Create
        vm_id = self.manager.create_vm(IsolationType.BROWSER_TAB)
        vm = self.manager.get_vm(vm_id)
        self.assertEqual(vm.get_state(), VMState.CREATED)

        # Destroy
        self.manager.destroy_vm(vm_id)
        self.assertIsNone(self.manager.get_vm(vm_id))

    def test_comprehensive_logging(self):
        """Test that logging is configured"""
        vm_id = self.manager.create_vm(IsolationType.BROWSER_TAB)
        vm = self.manager.get_vm(vm_id)

        # Logger should be configured
        self.assertIsNotNone(vm.logger)
        self.assertIsNotNone(self.manager.logger)


if __name__ == "__main__":
    unittest.main()
