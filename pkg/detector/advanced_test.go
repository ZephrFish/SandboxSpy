package detector

import (
	"runtime"
	"testing"
)

func TestAdvancedDetector(t *testing.T) {
	d := New()
	advDetector := &AdvancedDetector{Detector: d}
	
	// Test that methods don't panic
	t.Run("CheckInjectedDLLs", func(t *testing.T) {
		dlls := advDetector.CheckInjectedDLLs()
		// Should return empty slice or actual DLLs, not panic
		if dlls == nil {
			t.Error("CheckInjectedDLLs should not return nil")
		}
	})
	
	t.Run("CheckSpecificMACs", func(t *testing.T) {
		macs := advDetector.CheckSpecificMACs()
		// Should return map, possibly empty
		if macs == nil {
			t.Error("CheckSpecificMACs should not return nil")
		}
	})
	
	t.Run("CheckExtendedUsernames", func(t *testing.T) {
		// This will check current username
		_ = advDetector.CheckExtendedUsernames()
		// Should not panic
	})
	
	t.Run("IsDebuggerPresent", func(t *testing.T) {
		// Should return false in normal test environment
		result := advDetector.IsDebuggerPresent()
		// Just verify it returns a boolean without panicking
		_ = result
	})
	
	t.Run("ScanMemoryArtifacts", func(t *testing.T) {
		// Should safely check memory without crashing
		_ = advDetector.ScanMemoryArtifacts()
	})
	
	t.Run("CheckFilesystemArtifacts", func(t *testing.T) {
		// Should check for files without crashing
		_ = advDetector.CheckFilesystemArtifacts()
	})
	
	if runtime.GOOS == "windows" {
		t.Run("CheckWMIPortConnectors", func(t *testing.T) {
			// Windows-specific test
			_ = advDetector.CheckWMIPortConnectors()
		})
		
		t.Run("CheckWMISystemInfo", func(t *testing.T) {
			// Windows-specific test
			info := advDetector.CheckWMISystemInfo()
			// Should return string or empty string
			_ = info
		})
		
		t.Run("CheckRegistryArtifacts", func(t *testing.T) {
			// Windows-specific test
			_ = advDetector.CheckRegistryArtifacts()
		})
	}
	
	t.Run("AggressiveTimingCheck", func(t *testing.T) {
		// Should perform timing check without issues
		_ = advDetector.AggressiveTimingCheck()
	})
}

func TestAdvancedIntegration(t *testing.T) {
	// Test that advanced detection integrates with main detector
	d := New()
	
	// Run full detection with advanced checks
	result := d.RunAllDetections()
	
	if result == nil {
		t.Fatal("RunAllDetections with advanced checks returned nil")
	}
	
	// Check that advanced metadata fields are present
	if _, ok := result.Metadata["total_checks"]; !ok {
		t.Error("Missing total_checks in metadata")
	}
	
	if _, ok := result.Metadata["positive_checks"]; !ok {
		t.Error("Missing positive_checks in metadata")
	}
	
	// Verify tags array exists (may be empty)
	if result.Tags == nil {
		t.Error("Tags should not be nil")
	}
}

func BenchmarkAdvancedDetection(b *testing.B) {
	d := New()
	advDetector := &AdvancedDetector{Detector: d}
	
	b.Run("CheckInjectedDLLs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = advDetector.CheckInjectedDLLs()
		}
	})
	
	b.Run("CheckSpecificMACs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = advDetector.CheckSpecificMACs()
		}
	})
	
	b.Run("ScanMemoryArtifacts", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = advDetector.ScanMemoryArtifacts()
		}
	})
}