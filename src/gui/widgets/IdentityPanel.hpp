#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QGroupBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QFont>
#include "../../core/include/ncp_identity.hpp"

class IdentityPanel : public QWidget {
    Q_OBJECT
public:
    explicit IdentityPanel(ncp::DPI::IdentityRotation* rotation, QWidget* parent = nullptr)
        : QWidget(parent), rotation_(rotation) {
        auto* root = new QVBoxLayout(this);

        // ─── Current identity ───────────────────────────────────────────
        auto* currentBox = new QGroupBox(tr("Current device identity"), this);
        auto* currentForm = new QFormLayout(currentBox);
        hostLabel_   = new QLabel("—", currentBox);
        macLabel_    = new QLabel("—", currentBox);
        vendorLabel_ = new QLabel("—", currentBox);
        for (auto* lbl : {hostLabel_, macLabel_, vendorLabel_}) lbl->setFont(mono());
        currentForm->addRow(tr("Hostname:"), hostLabel_);
        currentForm->addRow(tr("MAC:"),      macLabel_);
        currentForm->addRow(tr("Vendor:"),   vendorLabel_);

        // ─── Rotation controls ──────────────────────────────────────────
        auto* rotBox = new QGroupBox(tr("Rotation"), this);
        auto* rotLayout = new QVBoxLayout(rotBox);

        auto* configRow = new QHBoxLayout;
        intervalSpin_ = new QSpinBox(rotBox);
        intervalSpin_->setRange(30, 86400);
        intervalSpin_->setSingleStep(30);
        intervalSpin_->setValue(300);
        intervalSpin_->setSuffix(" s");
        autoCheck_ = new QCheckBox(tr("Auto-rotate"), rotBox);
        configRow->addWidget(new QLabel(tr("Interval:"), rotBox));
        configRow->addWidget(intervalSpin_);
        configRow->addStretch(1);
        configRow->addWidget(autoCheck_);

        auto* buttonRow = new QHBoxLayout;
        auto* rotateNowBtn = new QPushButton(tr("Rotate now"), rotBox);
        auto* regenBtn     = new QPushButton(tr("Regenerate pool"), rotBox);
        buttonRow->addWidget(rotateNowBtn);
        buttonRow->addWidget(regenBtn);
        buttonRow->addStretch(1);

        rotLayout->addLayout(configRow);
        rotLayout->addLayout(buttonRow);

        // ─── Stats ──────────────────────────────────────────────────────
        auto* statsBox = new QGroupBox(tr("Statistics"), this);
        auto* statsForm = new QFormLayout(statsBox);
        rotTotalLabel_   = new QLabel("0", statsBox);
        macChgLabel_     = new QLabel("0", statsBox);
        hostChgLabel_    = new QLabel("0", statsBox);
        poolIdxLabel_    = new QLabel("—", statsBox);
        for (auto* lbl : {rotTotalLabel_, macChgLabel_, hostChgLabel_, poolIdxLabel_})
            lbl->setFont(mono());
        statsForm->addRow(tr("Rotations:"),         rotTotalLabel_);
        statsForm->addRow(tr("MAC changes:"),       macChgLabel_);
        statsForm->addRow(tr("Hostname changes:"),  hostChgLabel_);
        statsForm->addRow(tr("Current pool index:"), poolIdxLabel_);

        root->addWidget(currentBox);
        root->addWidget(rotBox);
        root->addWidget(statsBox);
        root->addStretch(1);

        connect(rotateNowBtn, &QPushButton::clicked, this, &IdentityPanel::rotateNow);
        connect(regenBtn,     &QPushButton::clicked, this, &IdentityPanel::regenerate);
        connect(autoCheck_,   &QCheckBox::toggled,   this, &IdentityPanel::toggleAuto);
        connect(intervalSpin_, qOverload<int>(&QSpinBox::valueChanged),
                this, [this](int) { if (autoCheck_->isChecked()) toggleAuto(true); });

        refreshFromCore();
    }

    // Called by MainWindow on a timer tick to keep stats fresh.
    void refresh() { refreshFromCore(); }

private slots:
    void rotateNow() {
        if (!rotation_) return;
        rotation_->rotate_now();
        refreshFromCore();
    }

    void regenerate() {
        if (!rotation_) return;
        rotation_->clear_pool();
        rotation_->generate_pool(8);
        rotation_->rotate_now();
        refreshFromCore();
    }

    void toggleAuto(bool on) {
        if (!rotation_) return;
        if (on) {
            ncp::DPI::RotationConfig cfg;
            cfg.interval_sec = static_cast<uint32_t>(intervalSpin_->value());
            cfg.pool_size    = 8;
            rotation_->stop();
            rotation_->start(cfg, [this](const ncp::DPI::DeviceIdentity&) {
                // Callback runs on the rotation worker thread — UI updates
                // must be queued back to the main thread.
                QMetaObject::invokeMethod(this, "refresh", Qt::QueuedConnection);
            });
        } else {
            rotation_->stop();
        }
    }

private:
    void refreshFromCore() {
        if (!rotation_) return;
        const auto id = rotation_->get_current();
        hostLabel_  ->setText(id.hostname.empty() ? "—" : QString::fromStdString(id.hostname));
        macLabel_   ->setText(formatMac(id.mac));
        vendorLabel_->setText(id.vendor.empty() ? "—" : QString::fromStdString(id.vendor));

        const auto stats = rotation_->get_stats();
        rotTotalLabel_->setText(QString::number(stats.rotations_total));
        macChgLabel_  ->setText(QString::number(stats.mac_changes));
        hostChgLabel_ ->setText(QString::number(stats.hostname_changes));
        poolIdxLabel_ ->setText(QString::number(stats.current_identity));
    }

    static QString formatMac(const std::array<uint8_t, 6>& m) {
        return QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                                 m[0], m[1], m[2], m[3], m[4], m[5]);
    }

    static QFont mono() {
        QFont f; f.setStyleHint(QFont::Monospace); f.setFamily("Menlo");
        return f;
    }

    ncp::DPI::IdentityRotation* rotation_;  // not owned
    QLabel* hostLabel_;
    QLabel* macLabel_;
    QLabel* vendorLabel_;
    QSpinBox*  intervalSpin_;
    QCheckBox* autoCheck_;
    QLabel* rotTotalLabel_;
    QLabel* macChgLabel_;
    QLabel* hostChgLabel_;
    QLabel* poolIdxLabel_;
};
