#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QGridLayout>
#include <QCheckBox>
#include <QPushButton>
#include <QLabel>
#include <vector>
#include <utility>
#include "../../core/include/ncp_dpi_advanced.hpp"

// Per-technique editor: shows every EvasionTechnique as a checkbox,
// grouped by layer (TCP / TLS / HTTP / IP / timing). Toggling a box
// calls AdvancedDPIBypass::set_technique_enabled on the live engine.
// Lets the user fine-tune the pipeline beyond the four built-in presets.
class DPIStrategyEditor : public QWidget {
    Q_OBJECT
public:
    explicit DPIStrategyEditor(ncp::DPI::AdvancedDPIBypass* engine,
                                QWidget* parent = nullptr)
        : QWidget(parent), engine_(engine) {
        auto* root = new QVBoxLayout(this);

        // Preset row at the top — the four built-in presets from the
        // engine. Selecting one updates all the individual checkboxes.
        auto* presetRow = new QHBoxLayout;
        presetRow->addWidget(new QLabel(tr("Apply preset:"), this));
        for (auto p : { Preset{"Minimal",    ncp::DPI::AdvancedDPIBypass::BypassPreset::MINIMAL},
                        Preset{"Moderate",   ncp::DPI::AdvancedDPIBypass::BypassPreset::MODERATE},
                        Preset{"Aggressive", ncp::DPI::AdvancedDPIBypass::BypassPreset::AGGRESSIVE},
                        Preset{"Stealth",    ncp::DPI::AdvancedDPIBypass::BypassPreset::STEALTH} }) {
            auto* b = new QPushButton(tr(p.label), this);
            connect(b, &QPushButton::clicked, this, [this, preset=p.preset]{
                if (engine_) engine_->apply_preset(preset);
                refreshFromEngine();
            });
            presetRow->addWidget(b);
        }
        presetRow->addStretch(1);
        root->addLayout(presetRow);

        // Grouped checkbox grids
        root->addWidget(makeGroup(tr("TCP"), {
            {"TCP segmentation",         ncp::DPI::EvasionTechnique::TCP_SEGMENTATION},
            {"TCP disorder",             ncp::DPI::EvasionTechnique::TCP_DISORDER},
            {"TCP overlap",              ncp::DPI::EvasionTechnique::TCP_OVERLAP},
            {"TCP OOB data",             ncp::DPI::EvasionTechnique::TCP_OOB_DATA},
            {"TCP window size tricks",   ncp::DPI::EvasionTechnique::TCP_WINDOW_SIZE},
            {"TCP timestamp edit",       ncp::DPI::EvasionTechnique::TCP_TIMESTAMP_EDIT},
            {"TCP RST confusion",        ncp::DPI::EvasionTechnique::TCP_RST_CONFUSION},
        }));
        root->addWidget(makeGroup(tr("TLS"), {
            {"TLS record split",         ncp::DPI::EvasionTechnique::TLS_RECORD_SPLIT},
            {"TLS padding",              ncp::DPI::EvasionTechnique::TLS_PADDING},
            {"TLS fake extension",       ncp::DPI::EvasionTechnique::TLS_FAKE_EXTENSION},
            {"TLS version confusion",    ncp::DPI::EvasionTechnique::TLS_VERSION_CONFUSION},
            {"TLS GREASE",               ncp::DPI::EvasionTechnique::TLS_GREASE},
        }));
        root->addWidget(makeGroup(tr("HTTP / SNI"), {
            {"HTTP header split",        ncp::DPI::EvasionTechnique::HTTP_HEADER_SPLIT},
            {"HTTP space trick",         ncp::DPI::EvasionTechnique::HTTP_SPACE_TRICK},
            {"SNI split",                ncp::DPI::EvasionTechnique::SNI_SPLIT},
            {"Fake SNI",                 ncp::DPI::EvasionTechnique::FAKE_SNI},
            {"HTTP case variation",      ncp::DPI::EvasionTechnique::HTTP_CASE_VARIATION},
            {"HTTP host confusion",      ncp::DPI::EvasionTechnique::HTTP_HOST_CONFUSION},
        }));
        root->addWidget(makeGroup(tr("IP / Timing"), {
            {"IP fragmentation",         ncp::DPI::EvasionTechnique::IP_FRAGMENTATION},
            {"IP TTL tricks",            ncp::DPI::EvasionTechnique::IP_TTL_TRICKS},
            {"IP ID randomization",      ncp::DPI::EvasionTechnique::IP_ID_RANDOMIZATION},
            {"Timing jitter",            ncp::DPI::EvasionTechnique::TIMING_JITTER},
            {"Timing throttle",          ncp::DPI::EvasionTechnique::TIMING_THROTTLE},
            {"Timing burst",             ncp::DPI::EvasionTechnique::TIMING_BURST},
        }));
        root->addStretch(1);

        refreshFromEngine();
    }

    void refreshFromEngine() {
        if (!engine_) return;
        const auto active = engine_->get_active_techniques();
        for (auto& [box, tech] : boxes_) {
            const QSignalBlocker b(box);
            box->setChecked(std::find(active.begin(), active.end(), tech) != active.end());
        }
    }

private:
    struct Preset { const char* label; ncp::DPI::AdvancedDPIBypass::BypassPreset preset; };
    using Row = std::pair<const char*, ncp::DPI::EvasionTechnique>;

    QGroupBox* makeGroup(const QString& title, const std::vector<Row>& rows) {
        auto* box = new QGroupBox(title, this);
        auto* grid = new QGridLayout(box);
        const int cols = 2;
        int r = 0, c = 0;
        for (const auto& [label, tech] : rows) {
            auto* cb = new QCheckBox(tr(label), box);
            grid->addWidget(cb, r, c);
            boxes_.emplace_back(cb, tech);
            connect(cb, &QCheckBox::toggled, this,
                    [this, tech](bool on) {
                if (engine_) engine_->set_technique_enabled(tech, on);
            });
            if (++c >= cols) { c = 0; ++r; }
        }
        return box;
    }

    ncp::DPI::AdvancedDPIBypass* engine_;
    std::vector<std::pair<QCheckBox*, ncp::DPI::EvasionTechnique>> boxes_;
};
