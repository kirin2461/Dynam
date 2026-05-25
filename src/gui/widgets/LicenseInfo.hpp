#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include "../../core/include/ncp_license.hpp"

// Note: widget class is global; the data struct is ncp::License::LicenseInfo.
class LicenseInfo : public QWidget {
    Q_OBJECT
public:
    explicit LicenseInfo(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        hwidLabel_ = new QLabel("HWID: —", this);
        statusLabel_ = new QLabel("No license loaded", this);
        activateButton_ = new QPushButton("Activate license…", this);
        layout->addWidget(hwidLabel_);
        layout->addWidget(statusLabel_);
        layout->addWidget(activateButton_);
        connect(activateButton_, &QPushButton::clicked, this, &LicenseInfo::activateClicked);
    }
    void setHWID(const QString& hwid) {
        hwidLabel_->setText("HWID: " + hwid);
    }
    void updateInfo(const ncp::License::LicenseInfo& info) {
        statusLabel_->setText(QString("Plan: %1 — %2 days remaining")
                                  .arg(QString::fromStdString(info.plan))
                                  .arg(info.days_remaining));
    }

signals:
    void activateClicked();

private:
    QLabel* hwidLabel_;
    QLabel* statusLabel_;
    QPushButton* activateButton_;
};
