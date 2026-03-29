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
var managerOnce sync.Once

// GetManager returns the singleton UI manager.
func GetManager() *Manager {
	managerOnce.Do(func() {
		rl, err := readline.NewEx(&readline.Config{
			InterruptPrompt: "^C",
			EOFPrompt:       "exit",
		})
		if err != nil {
			globalManager = &Manager{}
		} else {
			globalManager = &Manager{rl: rl}
		}
	})
	return globalManager
}

func (m *Manager) ClearScreen() {
	// Always attempt to clear using standard ANSI escape codes
	// \033[H: Home cursor
	// \033[2J: Clear screen
	fmt.Print("\033[H\033[2J")
}

func (m *Manager) Close() {
	if m.rl != nil {
		m.rl.Close()
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
