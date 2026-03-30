package module

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Module struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Category      string `json:"category"`
	Deps          string `json:"deps"`
	Critical      bool   `json:"critical"`
	Tools         string `json:"tools"`
	Desc          string `json:"desc"`
	Reqs          string `json:"reqs"`
	PCAP          bool   `json:"pcap"`
	Timed         bool   `json:"timed"`
	DecodeProfile string `json:"decode_profile"`
	FilePath      string `json:"file_path"`
}

func DiscoverModules(modDir string) ([]Module, error) {
	var modules []Module
	files, err := os.ReadDir(modDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sh") {
			continue
		}

		filePath := filepath.Join(modDir, file.Name())
		m, err := parseModuleMeta(filePath)
		if err == nil {
			modules = append(modules, *m)
		}
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].ID < modules[j].ID
	})

	return modules, nil
}

func parseModuleMeta(filePath string) (*Module, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	m := &Module{FilePath: filePath}
	m.ID = strings.ToUpper(strings.Split(filepath.Base(filePath), "_")[0])

	scanner := bufio.NewScanner(file)
	hasMeta := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "MODULE_META") {
			hasMeta = true
			continue
		}
		if !hasMeta {
			continue
		}
		if !strings.HasPrefix(line, "# ") {
			break
		}

		parts := strings.SplitN(strings.TrimPrefix(line, "# "), "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		val := strings.Trim(parts[1], "\"")

		switch key {
		case "NAME":
			m.Name = val
		case "CATEGORY":
			m.Category = val
		case "DEPS":
			m.Deps = val
		case "CRITICAL":
			m.Critical = (val == "yes")
		case "TOOLS":
			m.Tools = val
		case "DESC":
			m.Desc = val
		case "REQS":
			m.Reqs = val
		case "PCAP":
			m.PCAP = (val == "yes")
		case "TIMED":
			m.Timed = (val == "yes")
		case "DECODE":
			m.DecodeProfile = val
		}
	}

	if !hasMeta {
		return nil, os.ErrInvalid
	}
	return m, nil
}
