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
        technique_->addItems({"TCP fragmentation", "TLS SNI split", "Header reorder"});
        layout->addWidget(toggle_);
        layout->addWidget(technique_);
        connect(toggle_, &QCheckBox::toggled, this, &DPIControl::bypassToggled);
        connect(technique_, qOverload<int>(&QComboBox::currentIndexChanged),
                this, &DPIControl::techniqueChanged);
    }
    void setBypassEnabled(bool enabled) { toggle_->setChecked(enabled); }

signals:
    void bypassToggled(bool enabled);
    void techniqueChanged(int index);

private:
    QCheckBox* toggle_;
    QComboBox* technique_;
};
