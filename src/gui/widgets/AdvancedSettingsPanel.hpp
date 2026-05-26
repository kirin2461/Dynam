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
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QHeaderView>
#include <QHash>
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

        tree_ = new QTreeWidget(this);
        tree_->setColumnCount(3);
        tree_->setHeaderLabels({tr("Key"), tr("Type"), tr("Value")});
        tree_->setSelectionBehavior(QAbstractItemView::SelectRows);
        tree_->setSelectionMode(QAbstractItemView::SingleSelection);
        tree_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tree_->setAlternatingRowColors(true);
        tree_->header()->setStretchLastSection(true);
        tree_->setIndentation(16);
        root->addWidget(tree_, 1);

        connect(addBtn_,     &QPushButton::clicked, this, &AdvancedSettingsPanel::onAdd);
        connect(editBtn_,    &QPushButton::clicked, this, &AdvancedSettingsPanel::onEdit);
        connect(deleteBtn_,  &QPushButton::clicked, this, &AdvancedSettingsPanel::onDelete);
        connect(refreshBtn_, &QPushButton::clicked, this, &AdvancedSettingsPanel::refresh);
        connect(resetBtn_,   &QPushButton::clicked, this, &AdvancedSettingsPanel::onResetAll);
        connect(tree_,       &QTreeWidget::itemDoubleClicked,
                this, [this](QTreeWidgetItem*, int){ onEdit(); });

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
    // Rebuild the tree from QSettings::allKeys(). Keys are slash-paths;
    // we build a nested QTreeWidgetItem hierarchy where each ancestor
    // is created lazily on first use. The full key is stashed in
    // Qt::UserRole on leaves so the toolbar actions can recover it
    // from a selection without re-walking.
    void refresh() {
        const QString prevSelected = selectedKey();
        const QStringList prevExpanded = expandedPaths();
        tree_->clear();

        QSettings s;
        const QStringList keys = s.allKeys();

        // prefix-path → branch item, so each ancestor is created once.
        QHash<QString, QTreeWidgetItem*> nodes;
        for (const QString& fullKey : keys) {
            const QStringList parts = fullKey.split('/');
            QTreeWidgetItem* parent = tree_->invisibleRootItem();
            QString accum;
            // Walk every part except the last — those are branches
            for (int i = 0; i < parts.size() - 1; ++i) {
                accum = accum.isEmpty() ? parts[i]
                                         : (accum + "/" + parts[i]);
                auto it = nodes.constFind(accum);
                if (it == nodes.constEnd()) {
                    auto* branch = new QTreeWidgetItem(parent, {parts[i]});
                    branch->setFirstColumnSpanned(false);
                    QFont bold = branch->font(0);
                    bold.setBold(true);
                    branch->setFont(0, bold);
                    nodes.insert(accum, branch);
                    parent = branch;
                } else {
                    parent = it.value();
                }
            }
            // Last part is the leaf (the actual setting)
            const QString leafName = parts.last();
            const QVariant v = s.value(fullKey);
            auto* leaf = new QTreeWidgetItem(parent,
                {leafName, typeName(v), displayValue(v)});
            QFont mono;
            mono.setStyleHint(QFont::Monospace);
            mono.setFamily("Menlo");
            leaf->setFont(0, mono);
            leaf->setFont(2, mono);
            // Stash the full path on the leaf for selection mapping.
            leaf->setData(0, Qt::UserRole, fullKey);
        }
        tree_->expandAll();
        for (int c = 0; c < 2; ++c) tree_->resizeColumnToContents(c);

        // Best-effort restore: collapse any branches that the user
        // had collapsed, and reselect the previously-selected leaf.
        if (!prevExpanded.isEmpty()) {
            // We already expanded everything; collapse the ones missing
            // from prevExpanded if there was a previous state captured.
            for (auto it = nodes.constBegin(); it != nodes.constEnd(); ++it) {
                if (!prevExpanded.contains(it.key())) it.value()->setExpanded(false);
            }
        }
        if (!prevSelected.isEmpty()) {
            if (auto* item = findLeaf(prevSelected)) {
                tree_->setCurrentItem(item);
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
    // Returns the full slash-path of the currently selected *leaf*, or an
    // empty string if no item is selected or the selection is a branch.
    QString selectedKey() const {
        auto* item = tree_->currentItem();
        if (!item) return {};
        const QVariant tag = item->data(0, Qt::UserRole);
        return tag.isValid() ? tag.toString() : QString{};
    }

    // Snapshot of currently-expanded branch paths so refresh() can
    // preserve the user's view across an add/edit/delete cycle.
    QStringList expandedPaths() const {
        QStringList out;
        walkBranches(tree_->invisibleRootItem(), QString{},
                     [&out](const QString& path, QTreeWidgetItem* it){
            if (it->isExpanded()) out.append(path);
        });
        return out;
    }

    // Find the leaf item whose UserRole == fullKey. Used to restore
    // selection across refresh(). Returns nullptr if not found.
    QTreeWidgetItem* findLeaf(const QString& fullKey) {
        QTreeWidgetItem* found = nullptr;
        walkBranches(tree_->invisibleRootItem(), QString{},
                     [&found, &fullKey](const QString&, QTreeWidgetItem* it){
            for (int i = 0; i < it->childCount(); ++i) {
                auto* child = it->child(i);
                if (child->childCount() == 0 &&
                    child->data(0, Qt::UserRole).toString() == fullKey) {
                    found = child;
                }
            }
        });
        return found;
    }

    // Depth-first walk of all branch (non-leaf) items, invoking fn with
    // the accumulated slash-path. Leaf items are visited indirectly via
    // their parent branch.
    template <typename Fn>
    static void walkBranches(QTreeWidgetItem* node, const QString& path, Fn fn) {
        for (int i = 0; i < node->childCount(); ++i) {
            auto* child = node->child(i);
            const QString childPath = path.isEmpty()
                ? child->text(0)
                : (path + "/" + child->text(0));
            if (child->childCount() > 0) {
                fn(childPath, child);
                walkBranches(child, childPath, fn);
            }
        }
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

    QTreeWidget*  tree_;
    QPushButton*  addBtn_;
    QPushButton*  editBtn_;
    QPushButton*  deleteBtn_;
    QPushButton*  refreshBtn_;
    QPushButton*  resetBtn_;
};
