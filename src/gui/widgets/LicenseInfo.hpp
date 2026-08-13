#pragma once

#include <QWidget>
#include <QString>
#include "ncp_license.hpp"

class QLabel;
class QLineEdit;
class QPushButton;

// License panel: shows current key status, verifies new keys offline
// (Ed25519, same scheme as the web GUI), stores the key in QSettings.
class LicenseInfo : public QWidget {
    Q_OBJECT
public:
    explicit LicenseInfo(QWidget* parent = nullptr);

    void setHWID(const QString& hwid);
    void updateInfo(const ncp::License::LicenseInfo& info);  // API compat
    QString currentKey() const;

signals:
    void activateClicked();

private:
    void reloadFromSettings();

    QLabel* planLabel_;
    QLabel* statusLabel_;
    QLabel* hwidLabel_;
    QLineEdit* keyEdit_;
    QPushButton* applyBtn_;
    QLabel* verdictLabel_;
};
