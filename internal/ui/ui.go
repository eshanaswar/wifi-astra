package ui

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/chzyer/readline"
)

type Manager struct {
	rl   *readline.Instance
	once sync.Once
}

var globalManager *Manager
var managerMu sync.Mutex

// GetManager returns the singleton UI manager.
func GetManager() *Manager {
	managerMu.Lock()
	defer managerMu.Unlock()
	
	if globalManager == nil {
		globalManager = &Manager{}
	}
	
	if globalManager.rl == nil {
		rl, err := readline.NewEx(&readline.Config{
			InterruptPrompt: "^C",
			EOFPrompt:       "exit",
		})
		if err == nil {
			globalManager.rl = rl
		}
	}
	return globalManager
}

func (m *Manager) ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

func (m *Manager) Close() {
	managerMu.Lock()
	defer managerMu.Unlock()
	if m.rl != nil {
		m.rl.Close()
		m.rl = nil
	}
}

type MenuOption struct {
	Label  string
	Action func() error
}

type Menu struct {
	Title   string
	Options []MenuOption
	Prompt  string
}

func NewMenu(title string) *Menu {
	return &Menu{
		Title:   title,
		Options: []MenuOption{},
		Prompt:  "Select an option: ",
	}
}

func (m *Menu) AddOption(label string, action func() error) {
	m.Options = append(m.Options, MenuOption{
		Label:  label,
		Action: action,
	})
}

func (m *Menu) Display() error {
	mgr := GetManager()
	if mgr.rl == nil {
		return fmt.Errorf("UI manager not initialized")
	}

	for {
		fmt.Printf("\n--- %s ---\n", m.Title)
		for i, opt := range m.Options {
			fmt.Printf("%d) %s\n", i+1, opt.Label)
		}
		fmt.Printf("q) Quit / Back\n")

		mgr.rl.SetPrompt(m.Prompt)
		line, err := mgr.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt || err == io.EOF {
				break
			}
			return err
		}

		input := strings.TrimSpace(line)
		if input == "q" {
			break
		}

		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(m.Options) {
			fmt.Println("Invalid choice. Please try again.")
			continue
		}

		if err := m.Options[choice-1].Action(); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
	return nil
}

func PromptString(prompt string, defaultValue string) string {
	mgr := GetManager()
	if mgr.rl == nil {
		fmt.Print(prompt + ": ")
		var input string
		fmt.Scanln(&input)
		if input == "" { return defaultValue }
		return input
	}

	fullPrompt := prompt + ": "
	if defaultValue != "" {
		fullPrompt = fmt.Sprintf("%s [%s]: ", prompt, defaultValue)
	}
	
	mgr.rl.SetPrompt(fullPrompt)
	line, err := mgr.rl.Readline()
	if err != nil {
		if err.Error() == "Interrupt" || strings.Contains(strings.ToLower(err.Error()), "interrupt") {
			return ""
		}
		return defaultValue
	}

	input := strings.TrimSpace(line)
	if input == "" {
		return defaultValue
	}
	return input
}

func PromptConfirm(prompt string, defaultValue bool) bool {
	suffix := " [y/N]: "
	if defaultValue {
		suffix = " [Y/n]: "
	}

	mgr := GetManager()
	if mgr.rl == nil {
		fmt.Print(prompt + suffix)
		var input string
		fmt.Scanln(&input)
		input = strings.ToLower(input)
		if input == "y" { return true }
		return defaultValue
	}

	mgr.rl.SetPrompt(prompt + suffix)
	line, err := mgr.rl.Readline()
	if err != nil {
		return defaultValue
	}

	input := strings.ToLower(strings.TrimSpace(line))
	if input == "" {
		return defaultValue
	}
	return input == "y" || input == "yes"
}

func PromptList(title string, options []string) int {
	mgr := GetManager()
	if mgr.rl == nil {
		fmt.Printf("\n--- %s ---\n", title)
		for i, opt := range options {
			fmt.Printf("%d) %s\n", i+1, opt)
		}
		fmt.Print("Select an option: ")
		var input string
		fmt.Scanln(&input)
		choice, _ := strconv.Atoi(input)
		return choice - 1
	}

	fmt.Printf("\n--- %s ---\n", title)
	for i, opt := range options {
		fmt.Printf("%d) %s\n", i+1, opt)
	}

	for {
		mgr.rl.SetPrompt("Select an option: ")
		line, err := mgr.rl.Readline()
		if err != nil {
			return -1
		}

		input := strings.TrimSpace(line)
		if input == "" {
			return -1
		}

		choice, err := strconv.Atoi(input)
		if err != nil || choice < 1 || choice > len(options) {
			fmt.Println("Invalid choice. Please try again.")
			continue
		}

		return choice - 1
	}
}
