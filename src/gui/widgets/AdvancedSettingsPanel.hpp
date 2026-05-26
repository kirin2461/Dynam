#pragma once
#include <QWidget>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QSettings>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QFont>
#include <QMetaType>
#include <QVariant>

// Editor dialog for a single QSettings key. Used for both Add (key path
// editable) and Edit (key path readonly). The value-widget swaps to a
// type-appropriate control whenever the type combo changes.
class SettingEditorDialog : public QDialog {
    Q_OBJECT
public:
    SettingEditorDialog(const QString& key,
                         const QVariant& value,
                         bool keyEditable,
                         QWidget* parent = nullptr)
        : QDialog(parent) {
        setWindowTitle(keyEditable ? tr("Add setting") : tr("Edit setting"));
        setModal(true);
        resize(420, 220);

        auto* root = new QVBoxLayout(this);
        auto* form = new QFormLayout;

        keyEdit_ = new QLineEdit(key, this);
        keyEdit_->setReadOnly(!keyEditable);
        keyEdit_->setPlaceholderText("section/key");
        if (keyEditable) {
            QFont mono; mono.setStyleHint(QFont::Monospace); mono.setFamily("Menlo");
            keyEdit_->setFont(mono);
        }

        typeCombo_ = new QComboBox(this);
        typeCombo_->addItem("String", static_cast<int>(QMetaType::QString));
        typeCombo_->addItem("Bool",   static_cast<int>(QMetaType::Bool));
        typeCombo_->addItem("Int",    static_cast<int>(QMetaType::Int));
        typeCombo_->addItem("Double", static_cast<int>(QMetaType::Double));

        valueHolder_ = new QWidget(this);
        valueLayout_ = new QVBoxLayout(valueHolder_);
        valueLayout_->setContentsMargins(0, 0, 0, 0);

        form->addRow(tr("Key:"),   keyEdit_);
        form->addRow(tr("Type:"),  typeCombo_);
        form->addRow(tr("Value:"), valueHolder_);
        root->addLayout(form);

        auto* note = new QLabel(tr(
            "Use forward-slash for nested keys (e.g. <code>ui/theme</code>). "
            "Changing the type recreates the editor."), this);
        note->setStyleSheet("color:#888; font-size:11px;");
        note->setWordWrap(true);
        root->addWidget(note);
        root->addStretch(1);

        auto* bb = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);
        root->addWidget(bb);

        // Seed type from existing value
        const QMetaType::Type t = static_cast<QMetaType::Type>(value.typeId());
        int idx = typeCombo_->findData(static_cast<int>(t));
        if (idx < 0) idx = 0;  // unknown → treat as string
        typeCombo_->setCurrentIndex(idx);
        connect(typeCombo_, qOverload<int>(&QComboBox::currentIndexChanged),
                this, [this]{ rebuildEditor({}); });
        rebuildEditor(value);
    }

    QString  key()   const { return keyEdit_->text().trimmed(); }
    QVariant value() const {
        switch (currentType()) {
            case QMetaType::Bool:   return QVariant::fromValue(boolEditor_->isChecked());
            case QMetaType::Int:    return QVariant::fromValue(intEditor_->value());
            case QMetaType::Double: return QVariant::fromValue(doubleEditor_->value());
            case QMetaType::QString:
            default:                return QVariant::fromValue(stringEditor_->text());
        }
    }

private:
    QMetaType::Type currentType() const {
        return static_cast<QMetaType::Type>(typeCombo_->currentData().toInt());
    }

    // Tear down and rebuild the value editor whenever the type changes.
    // Pass the existing value through so type changes preserve data where
    // possible (e.g. switching String→Int reads the string as an integer).
    void rebuildEditor(const QVariant& seed) {
        // Clear previous editor
        while (auto* item = valueLayout_->takeAt(0)) {
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
        stringEditor_ = nullptr;
        boolEditor_   = nullptr;
        intEditor_    = nullptr;
        doubleEditor_ = nullptr;

        switch (currentType()) {
            case QMetaType::Bool:
                boolEditor_ = new QCheckBox(tr("true"), valueHolder_);
                boolEditor_->setChecked(seed.toBool());
                valueLayout_->addWidget(boolEditor_);
                break;
            case QMetaType::Int:
                intEditor_ = new QSpinBox(valueHolder_);
                intEditor_->setRange(INT_MIN, INT_MAX);
                intEditor_->setValue(seed.toInt());
                valueLayout_->addWidget(intEditor_);
                break;
            case QMetaType::Double:
                doubleEditor_ = new QDoubleSpinBox(valueHolder_);
                doubleEditor_->setRange(-1e15, 1e15);
                doubleEditor_->setDecimals(6);
                doubleEditor_->setValue(seed.toDouble());
                valueLayout_->addWidget(doubleEditor_);
                break;
            case QMetaType::QString:
            default:
                stringEditor_ = new QLineEdit(seed.toString(), valueHolder_);
                QFont mono; mono.setStyleHint(QFont::Monospace); mono.setFamily("Menlo");
                stringEditor_->setFont(mono);
                valueLayout_->addWidget(stringEditor_);
                break;
        }
    }

    QLineEdit*      keyEdit_;
    QComboBox*      typeCombo_;
    QWidget*        valueHolder_;
    QVBoxLayout*    valueLayout_;
    QLineEdit*      stringEditor_ = nullptr;
    QCheckBox*      boolEditor_   = nullptr;
    QSpinBox*       intEditor_    = nullptr;
    QDoubleSpinBox* doubleEditor_ = nullptr;
};

// AdvancedSettingsPanel — flat table of every QSettings key under the
// current organization/application. Read-only view of QSettings::allKeys()
// with Add / Edit / Delete buttons; every mutation re-reads the store.
class AdvancedSettingsPanel : public QWidget {
    Q_OBJECT
public:
    explicit AdvancedSettingsPanel(QWidget* parent = nullptr) : QWidget(parent) {
        auto* root = new QVBoxLayout(this);

        auto* row = new QHBoxLayout;
        addBtn_     = new QPushButton(tr("Add key…"), this);
        editBtn_    = new QPushButton(tr("Edit…"), this);
        deleteBtn_  = new QPushButton(tr("Delete"), this);
        refreshBtn_ = new QPushButton(tr("Refresh"), this);
        resetBtn_   = new QPushButton(tr("Reset all…"), this);
        resetBtn_->setStyleSheet("color:#e74c3c;");
        row->addWidget(addBtn_);
        row->addWidget(editBtn_);
        row->addWidget(deleteBtn_);
        row->addStretch(1);
        row->addWidget(refreshBtn_);
        row->addWidget(resetBtn_);
        root->addLayout(row);

        table_ = new QTableWidget(this);
        table_->setColumnCount(3);
        table_->setHorizontalHeaderLabels({tr("Key"), tr("Type"), tr("Value")});
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setSelectionMode(QAbstractItemView::SingleSelection);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table_->setAlternatingRowColors(true);
        table_->verticalHeader()->setVisible(false);
        table_->horizontalHeader()->setStretchLastSection(true);
        root->addWidget(table_, 1);

        connect(addBtn_,     &QPushButton::clicked, this, &AdvancedSettingsPanel::onAdd);
        connect(editBtn_,    &QPushButton::clicked, this, &AdvancedSettingsPanel::onEdit);
        connect(deleteBtn_,  &QPushButton::clicked, this, &AdvancedSettingsPanel::onDelete);
        connect(refreshBtn_, &QPushButton::clicked, this, &AdvancedSettingsPanel::refresh);
        connect(resetBtn_,   &QPushButton::clicked, this, &AdvancedSettingsPanel::onResetAll);
        connect(table_,      &QTableWidget::doubleClicked, this, &AdvancedSettingsPanel::onEdit);

        auto* warn = new QLabel(tr(
            "<b>Warning</b> — this is the raw QSettings store. Type the wrong "
            "value into the wrong key and Dynam may misbehave on next launch. "
            "If something breaks, use <i>Reset all</i> or delete "
            "<code>~/Library/Preferences/com.NCP.NetworkControlProtocol.plist</code>."), this);
        warn->setWordWrap(true);
        warn->setStyleSheet("color:#888; font-size:11px; padding:4px;");
        root->addWidget(warn);

        refresh();
    }

private slots:
    void refresh() {
        QSettings s;
        const QStringList keys = s.allKeys();
        const QString selected = selectedKey();
        table_->setRowCount(keys.size());
        for (int r = 0; r < keys.size(); ++r) {
            const QString& k = keys[r];
            const QVariant v = s.value(k);
            setCell(r, 0, k, /*mono=*/true);
            setCell(r, 1, typeName(v));
            setCell(r, 2, displayValue(v), /*mono=*/true);
        }
        for (int c = 0; c < 2; ++c) table_->resizeColumnToContents(c);
        if (!selected.isEmpty()) {
            for (int r = 0; r < table_->rowCount(); ++r) {
                if (table_->item(r, 0)->text() == selected) {
                    table_->selectRow(r);
                    break;
                }
            }
        }
    }

    void onAdd() {
        auto* dlg = new SettingEditorDialog({}, QVariant(QString{}), true, this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        connect(dlg, &QDialog::accepted, this, [this, dlg]{
            const QString k = dlg->key();
            if (k.isEmpty()) {
                QMessageBox::warning(this, tr("Add setting"), tr("Key is required."));
                return;
            }
            QSettings().setValue(k, dlg->value());
            refresh();
        });
        dlg->show();
    }

    void onEdit() {
        const QString k = selectedKey();
        if (k.isEmpty()) return;
        const QVariant v = QSettings().value(k);
        auto* dlg = new SettingEditorDialog(k, v, false, this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        connect(dlg, &QDialog::accepted, this, [this, dlg]{
            QSettings().setValue(dlg->key(), dlg->value());
            refresh();
        });
        dlg->show();
    }

    void onDelete() {
        const QString k = selectedKey();
        if (k.isEmpty()) return;
        if (QMessageBox::question(this, tr("Delete setting"),
                tr("Delete <code>%1</code>?").arg(k))
            == QMessageBox::Yes) {
            QSettings().remove(k);
            refresh();
        }
    }

    void onResetAll() {
        const auto resp = QMessageBox::warning(this, tr("Reset all settings"),
            tr("This will erase EVERY QSettings key, including window "
               "geometry and onboarding state. Continue?"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (resp != QMessageBox::Yes) return;
        QSettings s;
        for (const QString& k : s.allKeys()) s.remove(k);
        refresh();
    }

private:
    QString selectedKey() const {
        const auto items = table_->selectedItems();
        if (items.isEmpty()) return {};
        return table_->item(items.first()->row(), 0)->text();
    }

    void setCell(int row, int col, const QString& text, bool mono = false) {
        auto* it = new QTableWidgetItem(text);
        it->setFlags(it->flags() & ~Qt::ItemIsEditable);
        if (mono) {
            QFont f; f.setStyleHint(QFont::Monospace); f.setFamily("Menlo");
            it->setFont(f);
        }
        table_->setItem(row, col, it);
    }

    static QString typeName(const QVariant& v) {
        switch (v.typeId()) {
            case QMetaType::Bool:        return "bool";
            case QMetaType::Int:         return "int";
            case QMetaType::LongLong:    return "int64";
            case QMetaType::Double:      return "double";
            case QMetaType::QString:     return "string";
            case QMetaType::QStringList: return "string[]";
            case QMetaType::QByteArray:  return "bytes";
        }
        return v.typeName() ? v.typeName() : "unknown";
    }

    static QString displayValue(const QVariant& v) {
        if (v.typeId() == QMetaType::QByteArray) {
            const auto ba = v.toByteArray();
            return QString("<%1 bytes>").arg(ba.size());
        }
        QString s = v.toString();
        if (s.size() > 80) s = s.left(80) + "…";
        return s;
    }

    QTableWidget* table_;
    QPushButton*  addBtn_;
    QPushButton*  editBtn_;
    QPushButton*  deleteBtn_;
    QPushButton*  refreshBtn_;
    QPushButton*  resetBtn_;
};
