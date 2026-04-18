package ui

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"wifi-astra/pkg/constants"

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

// PrintBanner prints the wifi-astra startup banner.
func (m *Manager) PrintBanner() {
	fmt.Printf("\n%s", constants.ThemeMission)
	fmt.Println(`  ██╗    ██╗██╗███████╗██╗      █████╗ ███████╗████████╗██████╗  █████╗ `)
	fmt.Println(`  ██║    ██║██║██╔════╝██║     ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗`)
	fmt.Println(`  ██║ █╗ ██║██║█████╗  ██║     ███████║███████╗   ██║   ██████╔╝███████║`)
	fmt.Println(`  ██║███╗██║██║██╔══╝  ██║     ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║`)
	fmt.Println(`  ╚███╔███╔╝██║██║     ██║     ██║  ██║███████║   ██║   ██║  ██║██║  ██║`)
	fmt.Println(`   ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝`)
	fmt.Printf("%s\n", constants.ColorReset)
	fmt.Printf("  %sWiFi Penetration Testing Framework%s  |  %sAuthorized Use Only%s\n\n",
		constants.ColorBold, constants.ColorReset, constants.ThemeHigh, constants.ColorReset)
}

// PrintHeader prints a themed section header.
func PrintHeader(title string) {
	fmt.Printf("\n%s%s%s\n", constants.ThemeHeader, strings.Repeat("═", 70), constants.ColorReset)
	fmt.Printf("%s  %s%s\n", constants.ThemeHeader, title, constants.ColorReset)
	fmt.Printf("%s%s%s\n", constants.ThemeHeader, strings.Repeat("─", 70), constants.ColorReset)
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
	Label        string
	DynamicLabel func() string
	Action       func() error
}

type Menu struct {
	Title     string
	Options   []MenuOption
	Prompt    string
	PreRender func() // called before rendering options each loop iteration
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

func (m *Menu) AddDynamicOption(dynamicLabel func() string, action func() error) {
	m.Options = append(m.Options, MenuOption{
		DynamicLabel: dynamicLabel,
		Action:       action,
	})
}

func (m *Menu) Display() error {
	mgr := GetManager()
	if mgr.rl == nil {
		return fmt.Errorf("UI manager not initialized")
	}

	for {
		mgr.ClearScreen()
		if m.PreRender != nil {
			m.PreRender()
		}
		PrintHeader(m.Title)
		for i, opt := range m.Options {
			label := opt.Label
			if opt.DynamicLabel != nil {
				label = opt.DynamicLabel()
			}
			fmt.Printf("%d) %s\n", i+1, label)
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
		PrintHeader(title)
		for i, opt := range options {
			fmt.Printf("%d) %s\n", i+1, opt)
		}
		fmt.Print("Select an option: ")
		var input string
		fmt.Scanln(&input)
		choice, _ := strconv.Atoi(input)
		return choice - 1
	}

	PrintHeader(title)
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
