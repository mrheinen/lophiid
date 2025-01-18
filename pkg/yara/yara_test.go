package yara

import (
	"fmt"
	"lophiid/pkg/database"
	"lophiid/pkg/database/models"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func setupTestDirectories(t *testing.T) (string, string, string) {
	baseDir := t.TempDir()
	rulesDir := filepath.Join(baseDir, "rules")
	scanDir := filepath.Join(baseDir, "scan")

	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("Failed to create rules directory: %v", err)
	}
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		t.Fatalf("Failed to create scan directory: %v", err)
	}

	return baseDir, rulesDir, scanDir
}

func TestYaraxWrapper_Init(t *testing.T) {
	y := &YaraxWrapper{}
	err := y.Init()
	if err != nil {
		t.Errorf("Init() error = %v, want nil", err)
	}
	if y.compiler == nil {
		t.Error("Init() compiler is nil, want non-nil")
	}
}

func TestYaraxWrapper_LoadRulesFromDirectory(t *testing.T) {
	// Setup
	_, rulesDir, _ := setupTestDirectories(t)
	validRule := `
rule test_rule {
    meta:
        author = "Test Author"
        description = "Test Description"
    strings:
        $a = "test string"
    condition:
        $a
}`

	err := os.WriteFile(filepath.Join(rulesDir, "test.yar"), []byte(validRule), 0644)
	if err != nil {
		t.Fatalf("Failed to write test rule: %v", err)
	}

	y := &YaraxWrapper{}
	err = y.Init()
	if err != nil {
		t.Fatalf("Failed to initialize Yara: %v", err)
	}

	// Test loading rules
	err = y.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		t.Errorf("LoadRulesFromDirectory() error = %v, want nil", err)
	}
}

func TestYaraxWrapper_ScanFile(t *testing.T) {
	// Setup
	_, rulesDir, scanDir := setupTestDirectories(t)

	// Create a test rule
	rule := `
rule test_rule {
    meta:
        author = "Test Author"
        description = "Test Description"
    strings:
        $a = "test content"
    condition:
        $a
}`

	err := os.WriteFile(filepath.Join(rulesDir, "test.yar"), []byte(rule), 0644)
	if err != nil {
		t.Fatalf("Failed to write test rule: %v", err)
	}

	// Create a test file to scan
	testContent := "this is test content to scan"
	testFile := filepath.Join(scanDir, "test.txt")
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Yara
	y := &YaraxWrapper{}
	err = y.Init()
	if err != nil {
		t.Fatalf("Failed to initialize Yara: %v", err)
	}

	// Load rules
	err = y.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Test scanning
	results, err := y.ScanFile(testFile)
	if err != nil {
		t.Errorf("ScanFile() error = %v, want nil", err)
	}
	if len(results) != 1 {
		t.Errorf("ScanFile() got %d results, want 1", len(results))
	}
	if len(results) > 0 && results[0].Identifier != "test_rule" {
		t.Errorf("ScanFile() got rule identifier %s, want test_rule", results[0].Identifier)
	}
}

func TestYaraxWrapper_ScanDirectoryRecursive(t *testing.T) {
	// Setup
	_, rulesDir, scanDir := setupTestDirectories(t)
	scanSubDir := filepath.Join(scanDir, "subdir")
	err := os.MkdirAll(scanSubDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create scan subdirectory: %v", err)
	}

	// Create a test rule
	rule := `
rule test_rule {
    meta:
        author = "Test Author"
        description = "Test Description"
    strings:
        $a = "test content"
    condition:
        $a
}`

	err = os.WriteFile(filepath.Join(rulesDir, "test.yar"), []byte(rule), 0644)
	if err != nil {
		t.Fatalf("Failed to write test rule: %v", err)
	}

	// Create test files to scan
	testContent := "this is test content to scan"
	testFile1 := filepath.Join(scanDir, "test1.txt")
	testFile2 := filepath.Join(scanSubDir, "test2.txt")

	err = os.WriteFile(testFile1, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file 1: %v", err)
	}
	err = os.WriteFile(testFile2, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file 2: %v", err)
	}

	// Initialize Yara
	y := &YaraxWrapper{}
	err = y.Init()
	if err != nil {
		t.Fatalf("Failed to initialize Yara: %v", err)
	}

	// Load rules
	err = y.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Test scanning
	matchCount := 0
	err = y.ScanDirectoryRecursive(scanDir, func(path string, results []YaraResult) {
		matchCount++
		if len(results) != 1 {
			t.Errorf("ScanDirectoryRecursive() got %d results for %s, want 1", len(results), path)
		}
		if len(results) > 0 && results[0].Identifier != "test_rule" {
			t.Errorf("ScanDirectoryRecursive() got rule identifier %s, want test_rule", results[0].Identifier)
		}
	})

	if err != nil {
		t.Errorf("ScanDirectoryRecursive() error = %v, want nil", err)
	}
	if matchCount != 2 {
		t.Errorf("ScanDirectoryRecursive() got %d matches, want 2", matchCount)
	}
}

func TestYaraResultMetadata(t *testing.T) {
	// Setup
	_, rulesDir, scanDir := setupTestDirectories(t)

	// Create a test rule with metadata
	rule := `
rule test_rule {
    meta:
        author = "Test Author"
        description = "Test Description"
        reference = "Test Reference"
        malpedia_reference = "Test Malpedia"
    strings:
        $a = "test content"
    condition:
        $a
}`

	err := os.WriteFile(filepath.Join(rulesDir, "test.yar"), []byte(rule), 0644)
	if err != nil {
		t.Fatalf("Failed to write test rule: %v", err)
	}

	testFile := filepath.Join(scanDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Yara
	y := &YaraxWrapper{}
	err = y.Init()
	if err != nil {
		t.Fatalf("Failed to initialize Yara: %v", err)
	}

	// Load rules
	err = y.LoadRulesFromDirectory(rulesDir)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Test scanning and metadata
	results, err := y.ScanFile(testFile)
	if err != nil {
		t.Fatalf("ScanFile() error = %v, want nil", err)
	}
	if len(results) != 1 {
		t.Fatalf("ScanFile() got %d results, want 1", len(results))
	}

	result := results[0]
	if result.Identifier != "test_rule" {
		t.Errorf("got rule identifier %s, want test_rule", result.Identifier)
	}

	// Check metadata
	expectedMetadata := map[string]string{
		"author":             "Test Author",
		"description":        "Test Description",
		"reference":          "Test Reference",
		"malpedia_reference": "Test Malpedia",
	}

	for _, md := range result.Metadata {
		expectedValue, exists := expectedMetadata[md.Identifier]
		if !exists {
			t.Errorf("unexpected metadata field: %s", md.Identifier)
			continue
		}
		if md.Value != expectedValue {
			t.Errorf("metadata %s = %v, want %v", md.Identifier, md.Value, expectedValue)
		}
	}
}

func TestGetPendingScanList(t *testing.T) {
	// Test cases
	tests := []struct {
		name           string
		limit          int64
		downloads      []models.Download
		expectedError  error
		expectedResult []models.Download
	}{
		{
			name:  "successful retrieval",
			limit: 50,
			downloads: []models.Download{
				{
					ID:           1,
					SHA256sum:    "abc123",
					YaraStatus:   "PENDING",
					FileLocation: "/tmp/test1.bin",
				},
				{
					ID:           2,
					SHA256sum:    "def456",
					YaraStatus:   "PENDING",
					FileLocation: "/tmp/test2.bin",
				},
			},
			expectedError:  nil,
			expectedResult: []models.Download{{ID: 1, SHA256sum: "abc123", YaraStatus: "PENDING", FileLocation: "/tmp/test1.bin"}, {ID: 2, SHA256sum: "def456", YaraStatus: "PENDING", FileLocation: "/tmp/test2.bin"}},
		},
		{
			name:           "database error",
			limit:          50,
			downloads:      nil,
			expectedError:  fmt.Errorf("test error"),
			expectedResult: []models.Download{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup fake client
			fakeClient := &database.FakeDatabaseClient{
				DownloadsToReturn: tt.downloads,
				ErrorToReturn:     tt.expectedError,
			}

			// Create YaraManager instance
			manager := NewYaraManager(fakeClient, "/test/rules")

			// Call the method
			result, err := manager.GetPendingScanList(tt.limit)

			// Check error
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			// Check result
			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("expected %+v, got %+v", tt.expectedResult, result)
			}
		})
	}
}

func TestScanDownloads(t *testing.T) {
	tests := []struct {
		name           string
		downloads      []models.Download
		yaraResults    []YaraResult
		yaraError      error
		expectedError  error
		expectedResult map[*models.Download][]YaraResult
	}{
		{
			name: "successful scan with matches",
			downloads: []models.Download{
				{
					ID:           1,
					FileLocation: "/tmp/test1.bin",
				},
				{
					ID:           2,
					FileLocation: "/tmp/test2.bin",
				},
			},
			yaraResults: []YaraResult{
				{
					Identifier: "malware_rule1",
					Tags:       []string{"malware", "trojan"},
					Metadata: []YaraResultMetadata{
						{Identifier: "author", Value: "Test Author"},
						{Identifier: "description", Value: "Test malware"},
					},
				},
			},
			yaraError:     nil,
			expectedError: nil,
		},
		{
			name: "scan with error",
			downloads: []models.Download{
				{
					ID:           1,
					FileLocation: "/tmp/test1.bin",
				},
			},
			yaraResults:   nil,
			yaraError:     fmt.Errorf("failed to scan file"),
			expectedError: fmt.Errorf("error scanning /tmp/test1.bin: failed to scan file"),
		},
		{
			name:           "empty downloads list",
			downloads:      []models.Download{},
			yaraResults:    []YaraResult{},
			yaraError:      nil,
			expectedError:  nil,
			expectedResult: map[*models.Download][]YaraResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup fake Yara
			fakeYara := &FakeYara{
				YaraResultsToReturn: tt.yaraResults,
				ErrorToReturn:       tt.yaraError,
			}

			// Create YaraManager instance
			manager := &YaraManager{
				dbClient:      nil, // not needed for this test
				rulesLocation: "/test/rules",
			}

			// Call the method
			downloads := tt.downloads
			result, err := manager.ScanDownloads(fakeYara, &downloads)

			// Check error
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// For successful cases with explicit expected results
			if tt.expectedResult != nil {
				if !reflect.DeepEqual(result, tt.expectedResult) {
					t.Errorf("expected %+v, got %+v", tt.expectedResult, result)
				}
				return
			}

			// For successful cases, verify each download has the expected results
			for dl := range result {
				if !reflect.DeepEqual(result[dl], tt.yaraResults) {
					t.Errorf("for file %s, expected %+v, got %+v",
						dl.FileLocation, tt.yaraResults, result[dl])
				}
			}
		})
	}
}

func TestStoreYaraResults(t *testing.T) {
	tests := []struct {
		name          string
		results       map[*models.Download][]YaraResult
		dbError       error
		expectedError error
		checkYara     func(*testing.T, *models.Yara)
	}{
		{
			name: "store with metadata",
			results: map[*models.Download][]YaraResult{
				{ID: 1}: {{
					Identifier: "test_rule",
					Tags:       []string{"malware"},
					Metadata: []YaraResultMetadata{
						{Identifier: "author", Value: "Test Author"},
						{Identifier: "reference", Value: "test-ref"},
						{Identifier: "is-ignored", Value: "is ignored"},
					},
				}},
			},
			checkYara: func(t *testing.T, y *models.Yara) {
				if y == nil {
					t.Fatalf("Yara is nil")
				}
				if y.Author != "Test Author" {
					t.Errorf("author = %q, want %q", y.Author, "Test Author")
				}
				if len(y.Metadata) != 2 {
					t.Errorf("metadata = %q, want 2", len(y.Metadata))
				}
			},
		},
		{
			name:          "database error",
			results:       map[*models.Download][]YaraResult{{ID: 1}: {{Identifier: "rule"}}},
			dbError:       fmt.Errorf("db error"),
			expectedError: fmt.Errorf("error inserting yara: {DownloadID:1 Identifier:rule} db error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeDB := &database.FakeDatabaseClient{
				ErrorToReturn: tt.dbError,
			}

			err := (&YaraManager{dbClient: fakeDB}).StoreYaraResults(tt.results)
			if tt.expectedError != nil && err == nil {
				t.Errorf("error = %v, want %v", err, tt.expectedError)
			}
			if tt.checkYara != nil && err == nil {
				tt.checkYara(t, fakeDB.LastDataModelSeen.(*models.Yara))
			}
		})
	}
}
