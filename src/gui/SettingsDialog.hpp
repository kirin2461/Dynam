#pragma once

#include <QDialog>
#include "ProxyController.hpp"

class QSpinBox;
class QLineEdit;
class QPlainTextEdit;

namespace ncp::GUI {

// Modal editor for proxy/chain settings (port, upstream, managed Tor).
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget* parent = nullptr);

    void setConfig(const GuiProxyConfig& cfg);
    GuiProxyConfig config() const;

private:
    QSpinBox* portSpin_;
    QLineEdit* upstreamEdit_;
    QLineEdit* torBinaryEdit_;
    QLineEdit* ptObfs4Edit_;
    QLineEdit* ptSnowflakeEdit_;
    QPlainTextEdit* bridgesEdit_;
};

} // namespace ncp::GUI
