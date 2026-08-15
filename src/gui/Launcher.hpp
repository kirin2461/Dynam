#pragma once

// UI launcher: lets the user pick between the native Qt GUI and the
// browser-based Web UI (ncp-gui.exe), with an optional remembered choice.
//
// Priority: --ui=qt|web (CLI) > saved QSettings "ui_mode" > ask dialog.

#include <QString>

class QWidget;

namespace ncp::GUI {
namespace Launcher {

enum class Mode { Qt, Web, Ask };

// Resolve which UI to start (does not show any UI itself).
Mode resolveMode();

// Modal chooser dialog. Returns the chosen mode; persists the choice to
// QSettings when the "remember" checkbox is ticked.
Mode promptMode(QWidget* parent = nullptr);

// Launch the Web UI (ncp-gui.exe located next to this executable).
// Returns true if the process was started; on failure shows a message box.
bool launchWebUi(QWidget* parent = nullptr);

// Forget the saved choice — the next start will ask again.
void resetChoice();

// Human-readable helper for logs/messages.
QString modeName(Mode m);

} // namespace Launcher
} // namespace ncp::GUI
