package yqfinger

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type YQFingerResult struct {
	Host                  string
	OriginURL             string
	OriginTitle           string
	OriginURLStatusCode    int
	SiteUp               string
	RedirectURL           string
	RedirectWebTitle      string
	RedirectURLStatusCode int
	FingerTag            string
}

type YQFingerClient struct {
	ExecutablePath string
	OutputPath    string
}

func NewYQFingerClient(yqfingerPath string) (*YQFingerClient, error) {
	if _, err := os.Stat(yqfingerPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("YQFinger executable not found: %s", yqfingerPath)
	}

	return &YQFingerClient{
		ExecutablePath: yqfingerPath,
		OutputPath:    "yqfinger.csv",
	}, nil
}

func (c *YQFingerClient) Detect(target string) ([]YQFingerResult, error) {
	cmd := exec.Command(c.ExecutablePath, "rule", "-u", target, "-o", c.OutputPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("YQFinger execution failed: %v, output: %s", err, string(output))
	}

	results, err := c.parseOutput()
	if err != nil {
		return nil, fmt.Errorf("parse YQFinger output failed: %v", err)
	}

	return results, nil
}

func (c *YQFingerClient) DetectBatch(targets []string) ([]YQFingerResult, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	targetFile := "yqfinger_targets.txt"
	err := c.writeTargetsToFile(targets, targetFile)
	if err != nil {
		return nil, fmt.Errorf("write targets to file failed: %v", err)
	}
	defer os.Remove(targetFile)

	cmd := exec.Command(c.ExecutablePath, "rule", "-f", targetFile, "-o", c.OutputPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("YQFinger execution failed: %v, output: %s", err, string(output))
	}

	results, err := c.parseOutput()
	if err != nil {
		return nil, fmt.Errorf("parse YQFinger output failed: %v", err)
	}

	return results, nil
}

func (c *YQFingerClient) parseOutput() ([]YQFingerResult, error) {
	file, err := os.Open(c.OutputPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = ','
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) <= 1 {
		return []YQFingerResult{}, nil
	}

	results := make([]YQFingerResult, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		record := records[i]
		if len(record) < 9 {
			continue
		}

		result := YQFingerResult{
			Host:                  record[0],
			OriginURL:             record[1],
			OriginTitle:           record[2],
			OriginURLStatusCode:    parseStatusCode(record[3]),
			SiteUp:               record[4],
			RedirectURL:           record[5],
			RedirectWebTitle:      record[6],
			RedirectURLStatusCode: parseStatusCode(record[7]),
			FingerTag:            record[8],
		}
		results = append(results, result)
	}

	return results, nil
}

func (c *YQFingerClient) writeTargetsToFile(targets []string, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, target := range targets {
		_, err := file.WriteString(target + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func parseStatusCode(statusStr string) int {
	var statusCode int
	fmt.Sscanf(statusStr, "%d", &statusCode)
	return statusCode
}

func GetYQFingerPath() (string, error) {
	possiblePaths := []string{
		"yqfinger_windows_amd64.exe",
		"yqfinger.exe",
		"YQFinger.exe",
		filepath.Join("..", "YQFinger-master", "yqfinger_windows_amd64.exe"),
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			absPath, err := filepath.Abs(path)
			if err != nil {
				continue
			}
			return absPath, nil
		}
	}

	return "", fmt.Errorf("YQFinger executable not found")
}

func ParseFingerTags(fingerTag string) []string {
	if fingerTag == "" {
		return []string{}
	}

	tags := strings.Split(fingerTag, ",")
	for i, tag := range tags {
		tags[i] = strings.TrimSpace(tag)
	}

	return tags
}
