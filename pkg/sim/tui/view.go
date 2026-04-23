package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/icellan/bsvm/pkg/sim"
)

// View renders the TUI into a string.
func (m *Model) View() string {
	if m.width == 0 {
		m.width = 100
	}
	if m.height == 0 {
		m.height = 30
	}
	header := m.renderHeader()
	nodes := m.renderNodes()
	workloads := m.renderWorkloads()
	users := m.renderUsers()
	events := m.renderEvents()
	footer := m.renderFooter()

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, workloads, users)
	body := lipgloss.JoinVertical(lipgloss.Left, header, nodes, topRow, events, footer)
	return body
}

func (m *Model) renderHeader() string {
	title := fmt.Sprintf(" BSVM Simulator  chain=%d  users=%d  tps5=%.1f tps30=%.1f ",
		m.stats.ChainID, m.stats.Users, m.stats.TPS5s, m.stats.TPS30s)
	return lipgloss.NewStyle().
		Bold(true).Foreground(ColorAccent).
		Background(ColorPanel).
		Width(m.width).Render(title)
}

func (m *Model) renderNodes() string {
	var rows []string
	for _, n := range m.stats.Nodes {
		status := OKStyle().Render("✓")
		if !n.Healthy {
			status = BadStyle().Render("✗")
		}
		err := ""
		if n.Err != "" {
			err = BadStyle().Render(" err=" + truncate(n.Err, 40))
		}
		rows = append(rows, fmt.Sprintf(
			"%s  %-30s  block=%-5d peers=%-2d prove=%s %s%s",
			status, n.URL, n.BlockNum, n.PeerCount, n.ProveMode, n.ProveState, err,
		))
	}
	content := TitleStyle().Render("Nodes") + "\n" + strings.Join(rows, "\n")
	return PanelStyle("Nodes", m.focus == PanelNodes).Width(m.width - 2).Render(content)
}

func (m *Model) renderWorkloads() string {
	var rows []string
	for i, w := range m.stats.Workloads {
		cursor := "  "
		if m.focus == PanelWorkloads && i == m.workloadIdx {
			cursor = OKStyle().Render("> ")
		}
		runStatus := MutedStyle().Render("(stopped)")
		if w.Running {
			runStatus = OKStyle().Render("(running)")
		}
		rows = append(rows, fmt.Sprintf("%s%-17s  %s  rate=%-3d  ok=%-5d err=%-4d  lat=%-4dms",
			cursor, w.Kind, runStatus, w.Rate, w.Succeeded, w.Failed, w.RollingLatency1))
	}
	content := TitleStyle().Render("Workloads") + "\n" + strings.Join(rows, "\n")
	w := (m.width - 4) * 6 / 10
	return PanelStyle("Workloads", m.focus == PanelWorkloads).Width(w).Render(content)
}

func (m *Model) renderUsers() string {
	users := m.engine.Pool.Users()
	var rows []string
	for i, u := range users {
		cursor := "  "
		if m.focus == PanelUsers && i == m.userIdx {
			cursor = OKStyle().Render("> ")
		}
		rows = append(rows, fmt.Sprintf("%s%-8s %s", cursor, u.Name, shortAddr(u.Address.Hex())))
	}
	content := TitleStyle().Render("Users") + "\n" + strings.Join(rows, "\n")
	w := (m.width - 4) * 4 / 10
	return PanelStyle("Users", m.focus == PanelUsers).Width(w).Render(content)
}

func (m *Model) renderEvents() string {
	lines := m.stats.Events
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	content := TitleStyle().Render("Recent events") + "\n" + strings.Join(lines, "\n")
	return PanelStyle("Events", false).Width(m.width - 2).Render(content)
}

func (m *Model) renderFooter() string {
	if m.showHelp {
		var parts []string
		for _, row := range m.keys.FullHelp() {
			var cells []string
			for _, b := range row {
				cells = append(cells, b.Help().Key+":"+b.Help().Desc)
			}
			parts = append(parts, strings.Join(cells, "  "))
		}
		return MutedStyle().Render(strings.Join(parts, "\n"))
	}
	var hints []string
	for _, b := range m.keys.ShortHelp() {
		hints = append(hints, MutedStyle().Render(b.Help().Key)+" "+b.Help().Desc)
	}
	timeStr := MutedStyle().Render(time.Now().Format("15:04:05"))
	return strings.Join(hints, "  ") + "   " + timeStr
}

func shortAddr(h string) string {
	if len(h) < 10 {
		return h
	}
	return h[:6] + ".." + h[len(h)-4:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// unused reference to sim to keep import even when View doesn't touch it.
var _ = sim.KindValueTransfer
