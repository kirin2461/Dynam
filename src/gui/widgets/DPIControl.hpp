#pragma once
#include <QWidget>
#include <QCheckBox>
#include <QComboBox>
#include <QVBoxLayout>

class DPIControl : public QWidget {
    Q_OBJECT
public:
    explicit DPIControl(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        toggle_ = new QCheckBox("Enable DPI bypass", this);
        technique_ = new QComboBox(this);
        // Order MUST match ncp::BypassTechnique in ncp_network.hpp so the
        // combo's currentIndex() can be cast straight to the enum.
        technique_->addItems({
            "None",
            "TTL modification",
            "TCP fragmentation",
            "SNI spoofing",
            "Fake packet",
            "Disorder",
            "Obfuscation",
            "HTTP mimicry",
            "TLS mimicry",
        });
        layout->addWidget(toggle_);
        layout->addWidget(technique_);
        connect(toggle_, &QCheckBox::toggled, this, &DPIControl::bypassToggled);
        connect(technique_, qOverload<int>(&QComboBox::currentIndexChanged),
                this, &DPIControl::techniqueChanged);
    }
    void setBypassEnabled(bool enabled) { toggle_->setChecked(enabled); }
    int currentTechniqueIndex() const   { return technique_->currentIndex(); }
    void setTechniqueIndex(int idx) {
        if (idx >= 0 && idx < technique_->count()) technique_->setCurrentIndex(idx);
    }

signals:
    void bypassToggled(bool enabled);
    void techniqueChanged(int index);

private:
    QCheckBox* toggle_;
    QComboBox* technique_;
};
