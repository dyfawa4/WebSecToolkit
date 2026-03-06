import os
import json
import random
import string
import itertools
import time
from datetime import datetime
from typing import Optional, Dict, Any, List, Generator
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QTextEdit, QComboBox, QCheckBox,
    QGroupBox, QScrollArea, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QTabWidget, QProgressBar,
    QSpinBox, QFileDialog, QMessageBox, QListView, QDialog,
    QListWidget, QDialogButtonBox, QFormLayout, QRadioButton,
    QButtonGroup, QPlainTextEdit, QTreeWidget, QTreeWidgetItem,
    QDateEdit, QCalendarWidget
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, QDate
from PyQt6.QtGui import QFont

from . import register_module
from gui.widgets.base_module import BaseModuleWidget, LogLevel


@register_module("password_gen")
class PasswordGenWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("密码生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        charset_group = QGroupBox("字符集设置")
        charset_layout = QVBoxLayout(charset_group)
        
        self._lower_cb = QCheckBox("小写字母 (a-z)")
        self._lower_cb.setChecked(True)
        charset_layout.addWidget(self._lower_cb)
        
        self._upper_cb = QCheckBox("大写字母 (A-Z)")
        self._upper_cb.setChecked(True)
        charset_layout.addWidget(self._upper_cb)
        
        self._digit_cb = QCheckBox("数字 (0-9)")
        self._digit_cb.setChecked(True)
        charset_layout.addWidget(self._digit_cb)
        
        self._special_cb = QCheckBox("特殊字符 (!@#$%^&*)")
        charset_layout.addWidget(self._special_cb)
        
        self._custom_cb = QCheckBox("自定义字符")
        charset_layout.addWidget(self._custom_cb)
        
        self._custom_chars = QLineEdit()
        self._custom_chars.setPlaceholderText("输入自定义字符")
        charset_layout.addWidget(self._custom_chars)
        
        layout.addWidget(charset_group)
        
        options_group = QGroupBox("生成选项")
        options_layout = QFormLayout(options_group)
        
        self._length_spin = QSpinBox()
        self._length_spin.setRange(1, 128)
        self._length_spin.setValue(16)
        options_layout.addRow("密码长度:", self._length_spin)
        
        self._count_spin = QSpinBox()
        self._count_spin.setRange(1, 10000)
        self._count_spin.setValue(10)
        options_layout.addRow("生成数量:", self._count_spin)
        
        self._exclude_similar = QCheckBox("排除相似字符 (0OIl1)")
        options_layout.addRow(self._exclude_similar)
        
        self._start_with_letter = QCheckBox("以字母开头")
        options_layout.addRow(self._start_with_letter)
        
        layout.addWidget(options_group)
        
        pattern_group = QGroupBox("密码模式")
        pattern_layout = QVBoxLayout(pattern_group)
        
        self._pattern_combo = QComboBox()
        self._setup_combo(self._pattern_combo, [
            "随机密码", "可记忆密码", "PIN码", "密码短语",
            "自定义模式"
        ])
        self._pattern_combo.currentTextChanged.connect(self._on_pattern_changed)
        pattern_layout.addWidget(QLabel("模式:"))
        pattern_layout.addWidget(self._pattern_combo)
        
        self._pattern_input = QLineEdit()
        self._pattern_input.setPlaceholderText("自定义模式: L=字母, D=数字, S=特殊, 如: LLD-DDSS")
        self._pattern_input.setVisible(False)
        pattern_layout.addWidget(self._pattern_input)
        
        layout.addWidget(pattern_group)
        
        btn_layout = QHBoxLayout()
        gen_btn = QPushButton("生成密码")
        gen_btn.clicked.connect(self._generate)
        
        save_btn = QPushButton("保存到文件")
        save_btn.setObjectName("secondaryButton")
        save_btn.clicked.connect(self._save_passwords)
        
        btn_layout.addWidget(gen_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        output_group = QGroupBox("生成结果")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(150)
        output_layout.addWidget(self._output_text)
        
        copy_btn = QPushButton("复制全部")
        copy_btn.setObjectName("secondaryButton")
        copy_btn.clicked.connect(self._copy_passwords)
        output_layout.addWidget(copy_btn)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _on_pattern_changed(self, pattern: str):
        self._pattern_input.setVisible(pattern == "自定义模式")
    
    def _generate(self):
        self._output_text.clear()
        
        length = self._length_spin.value()
        count = self._count_spin.value()
        pattern = self._pattern_combo.currentText()
        
        charset = ""
        if self._lower_cb.isChecked():
            charset += string.ascii_lowercase
        if self._upper_cb.isChecked():
            charset += string.ascii_uppercase
        if self._digit_cb.isChecked():
            charset += string.digits
        if self._special_cb.isChecked():
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if self._custom_cb.isChecked() and self._custom_chars.text():
            charset += self._custom_chars.text()
        
        if self._exclude_similar.isChecked():
            for c in "0OIl1":
                charset = charset.replace(c, '')
        
        if not charset:
            self._add_log(LogLevel.ERROR, "请至少选择一种字符集")
            return
        
        passwords = []
        for _ in range(count):
            if pattern == "随机密码":
                pwd = self._gen_random(charset, length)
            elif pattern == "可记忆密码":
                pwd = self._gen_memorable(length)
            elif pattern == "PIN码":
                pwd = ''.join(random.choices(string.digits, k=length))
            elif pattern == "密码短语":
                pwd = self._gen_passphrase(length)
            elif pattern == "自定义模式":
                pwd = self._gen_pattern(self._pattern_input.text(), charset)
            else:
                pwd = self._gen_random(charset, length)
            
            if self._start_with_letter.isChecked() and pwd and not pwd[0].isalpha():
                pwd = random.choice(string.ascii_letters) + pwd[1:]
            
            passwords.append(pwd)
        
        self._output_text.setPlainText('\n'.join(passwords))
        self._add_log(LogLevel.SUCCESS, f"已生成 {count} 个密码，长度 {length}")
        self._add_result(f"密码生成", f"{count}个", "完成", f"长度: {length}")
    
    def _gen_random(self, charset: str, length: int) -> str:
        return ''.join(random.choices(charset, k=length))
    
    def _gen_memorable(self, length: int) -> str:
        consonants = "bcdfghjklmnpqrstvwxz"
        vowels = "aeiou"
        result = []
        for i in range(length):
            if i % 2 == 0:
                result.append(random.choice(consonants))
            else:
                result.append(random.choice(vowels))
        return ''.join(result)
    
    def _gen_passphrase(self, word_count: int) -> str:
        words = ["apple", "banana", "cherry", "dragon", "eagle", "forest",
                 "garden", "house", "island", "jungle", "kitchen", "lemon",
                 "mountain", "night", "ocean", "palace", "queen", "river",
                 "sunset", "tiger", "umbrella", "valley", "water", "yellow"]
        selected = random.sample(words, min(word_count, len(words)))
        return '-'.join(selected)
    
    def _gen_pattern(self, pattern: str, charset: str) -> str:
        result = []
        for c in pattern:
            if c == 'L':
                result.append(random.choice(string.ascii_letters))
            elif c == 'D':
                result.append(random.choice(string.digits))
            elif c == 'S':
                result.append(random.choice("!@#$%^&*"))
            else:
                result.append(c)
        return ''.join(result)
    
    def _save_passwords(self):
        passwords = self._output_text.toPlainText()
        if not passwords:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存密码", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(passwords)
            self._add_log(LogLevel.SUCCESS, f"密码已保存到: {file_path}")
    
    def _copy_passwords(self):
        self._output_text.selectAll()
        self._output_text.copy()
        self._add_log(LogLevel.SUCCESS, "已复制到剪贴板")
    
    def _do_scan(self):
        self._generate()


@register_module("username_gen")
class UsernameGenWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("用户名生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        base_group = QGroupBox("基础信息")
        base_layout = QFormLayout(base_group)
        
        self._first_name = QLineEdit()
        self._first_name.setPlaceholderText("名字，如: John")
        base_layout.addRow("名字:", self._first_name)
        
        self._last_name = QLineEdit()
        self._last_name.setPlaceholderText("姓氏，如: Smith")
        base_layout.addRow("姓氏:", self._last_name)
        
        self._nickname = QLineEdit()
        self._nickname.setPlaceholderText("昵称/中间名")
        base_layout.addRow("昵称:", self._nickname)
        
        self._company = QLineEdit()
        self._company.setPlaceholderText("公司/组织名")
        base_layout.addRow("公司:", self._company)
        
        self._year = QLineEdit()
        self._year.setPlaceholderText("年份，如: 1990")
        base_layout.addRow("年份:", self._year)
        
        layout.addWidget(base_group)
        
        pattern_group = QGroupBox("生成模式")
        pattern_layout = QVBoxLayout(pattern_group)
        
        self._patterns = [
            ("firstname.lastname", True),
            ("firstnamelastname", True),
            ("flastname", True),
            ("lastnamef", True),
            ("firstname", False),
            ("lastname", False),
            ("f.lastname", False),
            ("lastname.firstname", False),
            ("firstname_lastname", False),
            ("f.lastnameYYYY", False),
            ("firstnameYYYY", False),
            ("company_firstname", False),
        ]
        
        self._pattern_checks = {}
        for pattern, checked in self._patterns:
            cb = QCheckBox(pattern)
            cb.setChecked(checked)
            self._pattern_checks[pattern] = cb
            pattern_layout.addWidget(cb)
        
        layout.addWidget(pattern_group)
        
        options_group = QGroupBox("选项")
        options_layout = QFormLayout(options_group)
        
        self._count_spin = QSpinBox()
        self._count_spin.setRange(1, 1000)
        self._count_spin.setValue(50)
        options_layout.addRow("生成数量上限:", self._count_spin)
        
        self._add_numbers = QCheckBox("添加数字后缀")
        options_layout.addRow(self._add_numbers)
        
        self._lowercase = QCheckBox("全部小写")
        self._lowercase.setChecked(True)
        options_layout.addRow(self._lowercase)
        
        layout.addWidget(options_group)
        
        gen_btn = QPushButton("生成用户名")
        gen_btn.clicked.connect(self._generate)
        layout.addWidget(gen_btn)
        
        output_group = QGroupBox("生成结果")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(200)
        output_layout.addWidget(self._output_text)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _generate(self):
        self._output_text.clear()
        
        first = self._first_name.text().strip()
        last = self._last_name.text().strip()
        nick = self._nickname.text().strip()
        company = self._company.text().strip()
        year = self._year.text().strip()
        
        max_count = self._count_spin.value()
        
        if not first and not last:
            self._add_log(LogLevel.ERROR, "请输入名字或姓氏")
            return
        
        usernames = set()
        
        f = first[0].lower() if first else ''
        l = last[0].lower() if last else ''
        first_lower = first.lower() if first else ''
        last_lower = last.lower() if last else ''
        nick_lower = nick.lower() if nick else ''
        company_lower = company.lower() if company else ''
        
        for pattern, cb in self._pattern_checks.items():
            if not cb.isChecked():
                continue
            
            template = pattern
            template = template.replace('firstname', '{first}')
            template = template.replace('lastname', '{last}')
            template = template.replace('f', '{f}')
            template = template.replace('l', '{l}')
            template = template.replace('YYYY', '{year}')
            template = template.replace('company', '{company}')
            
            username = template.format(
                first=first_lower, last=last_lower,
                f=f, l=l, year=year, company=company_lower
            )
            
            if self._lowercase.isChecked():
                username = username.lower()
            
            usernames.add(username)
            
            if self._add_numbers.isChecked():
                for num in range(1, 100):
                    usernames.add(f"{username}{num}")
        
        result = sorted(list(usernames))[:max_count]
        self._output_text.setPlainText('\n'.join(result))
        self._add_log(LogLevel.SUCCESS, f"已生成 {len(result)} 个用户名")
        self._add_result("用户名生成", f"{len(result)}个", "完成", f"基于: {first} {last}")
    
    def _do_scan(self):
        self._generate()


@register_module("dir_gen")
class DirGenWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("目录字典生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        target_group = QGroupBox("目标设置")
        target_layout = QFormLayout(target_group)
        
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("目标域名，如: example.com")
        target_layout.addRow("域名:", self._domain_input)
        
        self._tech_input = QLineEdit()
        self._tech_input.setPlaceholderText("技术栈，如: php,asp,jsp")
        target_layout.addRow("技术栈:", self._tech_input)
        
        layout.addWidget(target_group)
        
        dict_group = QGroupBox("字典类型")
        dict_layout = QVBoxLayout(dict_group)
        
        self._dict_types = [
            ("常见目录", True),
            ("备份文件", True),
            ("敏感文件", True),
            ("管理后台", True),
            ("上传目录", False),
            ("配置文件", False),
            ("日志文件", False),
            ("版本控制", False),
            ("API接口", False),
            ("自定义字典", False),
        ]
        
        self._type_checks = {}
        for dtype, checked in self._dict_types:
            cb = QCheckBox(dtype)
            cb.setChecked(checked)
            self._type_checks[dtype] = cb
            dict_layout.addWidget(cb)
        
        layout.addWidget(dict_group)
        
        options_group = QGroupBox("生成选项")
        options_layout = QFormLayout(options_group)
        
        self._extensions = QLineEdit()
        self._extensions.setText(".php,.asp,.aspx,.jsp,.html,.bak,.txt")
        options_layout.addRow("扩展名:", self._extensions)
        
        self._add_prefix = QCheckBox("添加常见前缀 (admin, backup, old)")
        options_layout.addRow(self._add_prefix)
        
        self._case_variants = QCheckBox("大小写变体")
        options_layout.addRow(self._case_variants)
        
        layout.addWidget(options_group)
        
        btn_layout = QHBoxLayout()
        gen_btn = QPushButton("生成字典")
        gen_btn.clicked.connect(self._generate)
        
        save_btn = QPushButton("保存字典")
        save_btn.setObjectName("secondaryButton")
        save_btn.clicked.connect(self._save_dict)
        
        btn_layout.addWidget(gen_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        output_group = QGroupBox("字典内容")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(200)
        output_layout.addWidget(self._output_text)
        
        self._count_label = QLabel("共 0 条")
        output_layout.addWidget(self._count_label)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _generate(self):
        self._output_text.clear()
        
        domain = self._domain_input.text().strip()
        tech = self._tech_input.text().strip().split(',')
        tech = [t.strip() for t in tech if t.strip()]
        
        extensions = [e.strip() for e in self._extensions.text().split(',') if e.strip()]
        
        directories = set()
        
        if self._type_checks["常见目录"].isChecked():
            directories.update([
                "admin", "administrator", "manage", "manager", "backend",
                "api", "app", "assets", "backup", "bak", "cache", "config",
                "data", "db", "demo", "doc", "docs", "download", "error",
                "files", "images", "img", "inc", "include", "install",
                "js", "lib", "logs", "media", "public", "scripts", "src",
                "static", "temp", "test", "tmp", "upload", "uploads", "user",
                "vendor", "web", "wp-admin", "wp-content", "wp-includes"
            ])
        
        if self._type_checks["备份文件"].isChecked():
            for ext in ['.bak', '.backup', '.old', '.copy', '.zip', '.tar', '.tar.gz', '.rar']:
                directories.update([
                    f"backup{ext}", f"backup{ext.replace('.', '')}",
                    f"www{ext}", f"web{ext}", f"site{ext}",
                    f"database{ext}", f"db{ext}", f"data{ext}"
                ])
        
        if self._type_checks["敏感文件"].isChecked():
            directories.update([
                ".git", ".git/config", ".git/HEAD", ".svn", ".svn/entries",
                ".hg", ".env", ".htaccess", ".htpasswd", "web.config",
                "robots.txt", "sitemap.xml", "crossdomain.xml",
                "phpinfo.php", "info.php", "test.php", "shell.php",
                "config.php", "database.yml", "credentials.json",
                ".DS_Store", "Thumbs.db", "desktop.ini"
            ])
        
        if self._type_checks["管理后台"].isChecked():
            directories.update([
                "admin", "admin.php", "admin/", "admin/login.php",
                "administrator", "administrator/", "admincp", "admincp/",
                "manage", "manage/", "manager", "manager/",
                "backend", "backend/", "console", "console/",
                "control", "control/", "cpanel", "cpanel/",
                "login", "login.php", "signin", "signin/",
                "wp-admin", "wp-login.php", "user/login",
                "admin.asp", "admin.aspx", "admin.jsp"
            ])
        
        if self._type_checks["上传目录"].isChecked():
            directories.update([
                "upload", "uploads", "uploadfiles", "uploaded",
                "files", "attachments", "media", "images",
                "upload.php", "uploadfile.php", "upfile.php"
            ])
        
        if self._type_checks["配置文件"].isChecked():
            for ext in extensions:
                directories.update([
                    f"config{ext}", f"configuration{ext}",
                    f"settings{ext}", f"db{ext}",
                    f"database{ext}", f"conn{ext}",
                    f"connect{ext}", f"connection{ext}"
                ])
        
        if self._type_checks["日志文件"].isChecked():
            directories.update([
                "logs", "log", "error.log", "access.log",
                "debug.log", "system.log", "application.log"
            ])
        
        if self._type_checks["版本控制"].isChecked():
            directories.update([
                ".git", ".git/config", ".git/HEAD", ".git/objects",
                ".svn", ".svn/entries", ".svn/wc.db",
                ".hg", ".hg/store", ".bzr", ".cvs"
            ])
        
        if self._type_checks["API接口"].isChecked():
            directories.update([
                "api", "api/v1", "api/v2", "api/v3",
                "rest", "restful", "graphql",
                "swagger", "swagger-ui", "api-docs",
                "openapi.json", "swagger.json"
            ])
        
        if self._add_prefix.isChecked():
            prefixes = ["admin", "backup", "old", "new", "test", "dev", "tmp"]
            new_dirs = set()
            for d in list(directories):
                for prefix in prefixes:
                    new_dirs.add(f"{prefix}-{d}")
                    new_dirs.add(f"{prefix}_{d}")
            directories.update(new_dirs)
        
        if self._case_variants.isChecked():
            new_dirs = set()
            for d in list(directories):
                new_dirs.add(d.upper())
                new_dirs.add(d.capitalize())
            directories.update(new_dirs)
        
        result = sorted(list(directories))
        self._output_text.setPlainText('\n'.join(result))
        self._count_label.setText(f"共 {len(result)} 条")
        
        self._add_log(LogLevel.SUCCESS, f"已生成 {len(result)} 条目录字典")
        self._add_result("目录字典", f"{len(result)}条", "完成", f"域名: {domain}")
    
    def _save_dict(self):
        content = self._output_text.toPlainText()
        if not content:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存字典", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._add_log(LogLevel.SUCCESS, f"字典已保存到: {file_path}")
    
    def _do_scan(self):
        self._generate()


@register_module("subdomain_gen")
class SubdomainGenWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("子域名字典生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        target_group = QGroupBox("目标域名")
        target_layout = QFormLayout(target_group)
        
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("主域名，如: example.com")
        target_layout.addRow("域名:", self._domain_input)
        
        layout.addWidget(target_group)
        
        dict_group = QGroupBox("子域名字典")
        dict_layout = QVBoxLayout(dict_group)
        
        self._dict_types = [
            ("常见子域名", True),
            ("云服务", True),
            ("开发测试", True),
            ("内部系统", False),
            ("服务监控", False),
            ("邮件服务", False),
            ("CDN相关", False),
            ("自定义前缀", False),
        ]
        
        self._type_checks = {}
        for dtype, checked in self._dict_types:
            cb = QCheckBox(dtype)
            cb.setChecked(checked)
            self._type_checks[dtype] = cb
            dict_layout.addWidget(cb)
        
        self._custom_prefix = QLineEdit()
        self._custom_prefix.setPlaceholderText("自定义前缀，逗号分隔: vpn,git,jenkins")
        dict_layout.addWidget(self._custom_prefix)
        
        layout.addWidget(dict_group)
        
        options_group = QGroupBox("生成选项")
        options_layout = QFormLayout(options_group)
        
        self._add_www = QCheckBox("添加www前缀")
        self._add_www.setChecked(True)
        options_layout.addRow(self._add_www)
        
        self._add_numbers = QCheckBox("添加数字后缀 (1-10)")
        options_layout.addRow(self._add_numbers)
        
        self._add_env = QCheckBox("添加环境后缀 (dev,test,staging,prod)")
        options_layout.addRow(self._add_env)
        
        layout.addWidget(options_group)
        
        btn_layout = QHBoxLayout()
        gen_btn = QPushButton("生成字典")
        gen_btn.clicked.connect(self._generate)
        
        save_btn = QPushButton("保存字典")
        save_btn.setObjectName("secondaryButton")
        save_btn.clicked.connect(self._save_dict)
        
        btn_layout.addWidget(gen_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        output_group = QGroupBox("子域名字典")
        output_layout = QVBoxLayout(output_group)
        
        self._output_text = QPlainTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(200)
        output_layout.addWidget(self._output_text)
        
        self._count_label = QLabel("共 0 条")
        output_layout.addWidget(self._count_label)
        
        layout.addWidget(output_group)
        
        return widget
    
    def _generate(self):
        self._output_text.clear()
        
        domain = self._domain_input.text().strip()
        if not domain:
            self._add_log(LogLevel.ERROR, "请输入目标域名")
            return
        
        subdomains = set()
        
        if self._type_checks["常见子域名"].isChecked():
            subdomains.update([
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
                "ns1", "ns2", "vpn", "blog", "shop", "store", "app", "api",
                "dev", "test", "staging", "prod", "demo", "portal", "secure",
                "admin", "panel", "cpanel", "webdisk", "autodiscover",
                "autoconfig", "mobile", "m", "wap", "forum", "forums",
                "wiki", "docs", "help", "support", "status", "cdn"
            ])
        
        if self._type_checks["云服务"].isChecked():
            subdomains.update([
                "aws", "azure", "gcp", "cloud", "s3", "ec2",
                "lambda", "cloudfront", "cloudflare", "akamai",
                "fastly", "heroku", "digitalocean", "linode"
            ])
        
        if self._type_checks["开发测试"].isChecked():
            subdomains.update([
                "dev", "development", "test", "testing", "staging",
                "stage", "uat", "qa", "sandbox", "beta", "alpha",
                "ci", "jenkins", "gitlab", "github", "git", "svn",
                "build", "deploy", "artifact", "nexus", "sonar"
            ])
        
        if self._type_checks["内部系统"].isChecked():
            subdomains.update([
                "internal", "intranet", "portal", "erp", "crm",
                "oa", "hr", "finance", "accounting", "payroll",
                "inventory", "warehouse", "logistics", "supply"
            ])
        
        if self._type_checks["服务监控"].isChecked():
            subdomains.update([
                "monitor", "monitoring", "grafana", "prometheus",
                "zabbix", "nagios", "alertmanager", "kibana",
                "elasticsearch", "logstash", "splunk", "datadog"
            ])
        
        if self._type_checks["邮件服务"].isChecked():
            subdomains.update([
                "mail", "email", "smtp", "pop", "pop3", "imap",
                "webmail", "mx", "mx1", "mx2", "exchange", "owa"
            ])
        
        if self._type_checks["CDN相关"].isChecked():
            subdomains.update([
                "cdn", "static", "assets", "images", "img", "video",
                "videos", "media", "files", "download", "dl", "cache"
            ])
        
        if self._type_checks["自定义前缀"].isChecked():
            custom = self._custom_prefix.text().strip().split(',')
            subdomains.update([c.strip() for c in custom if c.strip()])
        
        if self._add_numbers.isChecked():
            new_subs = set()
            for sub in list(subdomains):
                for i in range(1, 11):
                    new_subs.add(f"{sub}{i}")
            subdomains.update(new_subs)
        
        if self._add_env.isChecked():
            envs = ["dev", "test", "staging", "prod", "uat"]
            new_subs = set()
            for sub in list(subdomains):
                for env in envs:
                    new_subs.add(f"{sub}-{env}")
                    new_subs.add(f"{sub}.{env}")
            subdomains.update(new_subs)
        
        result = [f"{sub}.{domain}" for sub in sorted(subdomains)]
        
        if self._add_www.isChecked():
            result.insert(0, domain)
            result.insert(1, f"www.{domain}")
        
        self._output_text.setPlainText('\n'.join(result))
        self._count_label.setText(f"共 {len(result)} 条")
        
        self._add_log(LogLevel.SUCCESS, f"已生成 {len(result)} 条子域名字典")
        self._add_result("子域名字典", f"{len(result)}条", "完成", f"域名: {domain}")
    
    def _save_dict(self):
        content = self._output_text.toPlainText()
        if not content:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存字典", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._add_log(LogLevel.SUCCESS, f"字典已保存到: {file_path}")
    
    def _do_scan(self):
        self._generate()


@register_module("dict_manager")
class DictManagerWidget(BaseModuleWidget):
    def __init__(self):
        self._dicts = {}
        super().__init__("字典管理")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        toolbar_layout = QHBoxLayout()
        
        import_btn = QPushButton("导入字典")
        import_btn.clicked.connect(self._import_dict)
        
        create_btn = QPushButton("新建字典")
        create_btn.clicked.connect(self._create_dict)
        
        merge_btn = QPushButton("合并字典")
        merge_btn.clicked.connect(self._merge_dicts)
        
        toolbar_layout.addWidget(import_btn)
        toolbar_layout.addWidget(create_btn)
        toolbar_layout.addWidget(merge_btn)
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)
        
        self._dict_tree = QTreeWidget()
        self._dict_tree.setHeaderLabels(["字典名称", "条目数", "大小", "路径"])
        self._dict_tree.setColumnWidth(0, 200)
        layout.addWidget(self._dict_tree)
        
        preview_group = QGroupBox("字典预览")
        preview_layout = QVBoxLayout(preview_group)
        
        self._preview_text = QPlainTextEdit()
        self._preview_text.setReadOnly(True)
        self._preview_text.setMaximumHeight(150)
        preview_layout.addWidget(self._preview_text)
        
        self._dict_tree.itemClicked.connect(self._preview_dict)
        
        layout.addWidget(preview_group)
        
        action_layout = QHBoxLayout()
        
        dedup_btn = QPushButton("去重")
        dedup_btn.clicked.connect(self._deduplicate)
        
        sort_btn = QPushButton("排序")
        sort_btn.clicked.connect(self._sort_dict)
        
        export_btn = QPushButton("导出选中")
        export_btn.clicked.connect(self._export_selected)
        
        delete_btn = QPushButton("删除选中")
        delete_btn.setObjectName("dangerButton")
        delete_btn.clicked.connect(self._delete_selected)
        
        action_layout.addWidget(dedup_btn)
        action_layout.addWidget(sort_btn)
        action_layout.addWidget(export_btn)
        action_layout.addWidget(delete_btn)
        action_layout.addStretch()
        layout.addLayout(action_layout)
        
        self._load_builtin_dicts()
        
        return widget
    
    def _load_builtin_dicts(self):
        builtin = [
            ("常用密码", "passwords/common.txt", "常用密码TOP1000"),
            ("弱密码", "passwords/weak.txt", "弱密码集合"),
            ("用户名", "usernames/common.txt", "常用用户名"),
            ("目录字典", "directories/common.txt", "常见Web目录"),
            ("子域名", "subdomains/common.txt", "常见子域名"),
        ]
        
        for name, path, desc in builtin:
            item = QTreeWidgetItem([name, "-", "-", path])
            item.setData(0, Qt.ItemDataRole.UserRole, path)
            self._dict_tree.addTopLevelItem(item)
    
    def _import_dict(self):
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        for file_path in file_paths:
            path = Path(file_path)
            if path.exists():
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                name = path.stem
                count = len(lines)
                size = path.stat().st_size
                
                item = QTreeWidgetItem([
                    name, str(count), f"{size} bytes", str(path)
                ])
                item.setData(0, Qt.ItemDataRole.UserRole, str(path))
                self._dict_tree.addTopLevelItem(item)
                
                self._dicts[str(path)] = [l.strip() for l in lines]
                self._add_log(LogLevel.SUCCESS, f"已导入: {name} ({count} 条)")
    
    def _create_dict(self):
        self._add_log(LogLevel.INFO, "请使用密码生成器或目录生成器创建字典")
    
    def _merge_dicts(self):
        selected = self._dict_tree.selectedItems()
        if len(selected) < 2:
            self._add_log(LogLevel.WARNING, "请选择至少两个字典进行合并")
            return
        
        merged = set()
        for item in selected:
            path = item.data(0, Qt.ItemDataRole.UserRole)
            if path in self._dicts:
                merged.update(self._dicts[path])
        
        name = "merged_" + datetime.now().strftime("%Y%m%d_%H%M%S")
        item = QTreeWidgetItem([
            name, str(len(merged)), "-", "merged"
        ])
        item.setData(0, Qt.ItemDataRole.UserRole, name)
        self._dict_tree.addTopLevelItem(item)
        self._dicts[name] = list(merged)
        
        self._add_log(LogLevel.SUCCESS, f"已合并 {len(selected)} 个字典，共 {len(merged)} 条")
    
    def _preview_dict(self, item: QTreeWidgetItem):
        path = item.data(0, Qt.ItemDataRole.UserRole)
        
        if path in self._dicts:
            lines = self._dicts[path][:100]
        elif Path(path).exists():
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [l.strip() for l in f.readlines()[:100]]
        else:
            self._preview_text.setPlainText("无法预览")
            return
        
        self._preview_text.setPlainText('\n'.join(lines))
    
    def _deduplicate(self):
        selected = self._dict_tree.selectedItems()
        for item in selected:
            path = item.data(0, Qt.ItemDataRole.UserRole)
            if path in self._dicts:
                original = len(self._dicts[path])
                self._dicts[path] = list(set(self._dicts[path]))
                deduped = len(self._dicts[path])
                item.setText(1, str(deduped))
                self._add_log(LogLevel.SUCCESS, f"去重完成: {original} -> {deduped}")
    
    def _sort_dict(self):
        selected = self._dict_tree.selectedItems()
        for item in selected:
            path = item.data(0, Qt.ItemDataRole.UserRole)
            if path in self._dicts:
                self._dicts[path] = sorted(self._dicts[path])
                self._add_log(LogLevel.SUCCESS, "排序完成")
    
    def _export_selected(self):
        selected = self._dict_tree.selectedItems()
        if not selected:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出字典", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                for item in selected:
                    path = item.data(0, Qt.ItemDataRole.UserRole)
                    if path in self._dicts:
                        f.write('\n'.join(self._dicts[path]) + '\n')
            self._add_log(LogLevel.SUCCESS, f"已导出到: {file_path}")
    
    def _delete_selected(self):
        selected = self._dict_tree.selectedItems()
        for item in selected:
            path = item.data(0, Qt.ItemDataRole.UserRole)
            if path in self._dicts:
                del self._dicts[path]
            self._dict_tree.takeTopLevelItem(self._dict_tree.indexOfTopLevelItem(item))
        self._add_log(LogLevel.SUCCESS, f"已删除 {len(selected)} 个字典")
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "使用上方按钮管理字典")


@register_module("report_gen")
class ReportGenWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("报告生成")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        info_group = QGroupBox("报告信息")
        info_layout = QFormLayout(info_group)
        
        self._project_name = QLineEdit()
        self._project_name.setPlaceholderText("项目名称")
        info_layout.addRow("项目名称:", self._project_name)
        
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("目标地址")
        info_layout.addRow("目标:", self._target_input)
        
        self._tester_input = QLineEdit()
        self._tester_input.setPlaceholderText("测试人员")
        info_layout.addRow("测试人员:", self._tester_input)
        
        self._date_edit = QDateEdit()
        self._date_edit.setDate(QDate.currentDate())
        info_layout.addRow("测试日期:", self._date_edit)
        
        layout.addWidget(info_group)
        
        format_group = QGroupBox("报告格式")
        format_layout = QVBoxLayout(format_group)
        
        self._format_group = QButtonGroup()
        formats = [("HTML", True), ("Markdown (.md)", False), ("PDF", False), ("Word (.doc)", False), ("JSON", False)]
        
        for i, (fmt, checked) in enumerate(formats):
            rb = QRadioButton(fmt)
            rb.setChecked(checked)
            self._format_group.addButton(rb, i)
            format_layout.addWidget(rb)
        
        layout.addWidget(format_group)
        
        content_group = QGroupBox("报告内容")
        content_layout = QVBoxLayout(content_group)
        
        self._include_summary = QCheckBox("执行摘要")
        self._include_summary.setChecked(True)
        content_layout.addWidget(self._include_summary)
        
        self._include_scope = QCheckBox("测试范围")
        self._include_scope.setChecked(True)
        content_layout.addWidget(self._include_scope)
        
        self._include_vulns = QCheckBox("漏洞详情")
        self._include_vulns.setChecked(True)
        content_layout.addWidget(self._include_vulns)
        
        self._include_remediation = QCheckBox("修复建议")
        self._include_remediation.setChecked(True)
        content_layout.addWidget(self._include_remediation)
        
        self._include_appendix = QCheckBox("附录")
        content_layout.addWidget(self._include_appendix)
        
        layout.addWidget(content_group)
        
        btn_layout = QHBoxLayout()
        
        gen_btn = QPushButton("生成报告")
        gen_btn.clicked.connect(self._generate_report)
        
        preview_btn = QPushButton("预览")
        preview_btn.setObjectName("secondaryButton")
        preview_btn.clicked.connect(self._preview_report)
        
        btn_layout.addWidget(gen_btn)
        btn_layout.addWidget(preview_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        return widget
    
    def _generate_report(self):
        project = self._project_name.text() or "未命名项目"
        target = self._target_input.text() or "未指定"
        tester = self._tester_input.text() or "匿名"
        date = self._date_edit.date().toString("yyyy-MM-dd")
        
        format_id = self._format_group.checkedId()
        formats = ["html", "md", "pdf", "doc", "json"]
        fmt = formats[format_id] if format_id >= 0 else "html"
        
        report = self._build_report(project, target, tester, date)
        
        ext_map = {"html": "html", "md": "md", "json": "json", "pdf": "pdf", "doc": "doc"}
        filter_map = {
            "html": "HTML 文件 (*.html)",
            "md": "Markdown 文件 (*.md)",
            "json": "JSON 文件 (*.json)",
            "pdf": "PDF 文件 (*.pdf)",
            "doc": "Word 文件 (*.doc)"
        }
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存报告", f"{project}_report.{ext_map.get(fmt, 'html')}",
            f"{filter_map.get(fmt, 'HTML 文件 (*.html)')}"
        )
        
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report)
            self._add_log(LogLevel.SUCCESS, f"报告已保存: {file_path}")
            self._add_result("报告生成", fmt.upper(), "完成", f"文件: {file_path}")
    
    def _build_report(self, project: str, target: str, tester: str, date: str) -> str:
        format_id = self._format_group.checkedId()
        
        if format_id == 4:
            return self._build_json_report(project, target, tester, date)
        elif format_id == 1:
            return self._build_md_report(project, target, tester, date)
        elif format_id == 2:
            return self._build_pdf_report(project, target, tester, date)
        elif format_id == 3:
            return self._build_doc_report(project, target, tester, date)
        else:
            return self._build_html_report(project, target, tester, date)
    
    def _build_html_report(self, project: str, target: str, tester: str, date: str) -> str:
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>安全测试报告 - {project}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #007bff; margin-top: 30px; }}
        .info {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
        .vuln {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .high {{ border-left: 4px solid #dc3545; }}
        .medium {{ border-left: 4px solid #ffc107; }}
        .low {{ border-left: 4px solid #28a745; }}
    </style>
</head>
<body>
    <h1>安全测试报告</h1>
    
    <div class="info">
        <p><strong>项目名称:</strong> {project}</p>
        <p><strong>目标地址:</strong> {target}</p>
        <p><strong>测试人员:</strong> {tester}</p>
        <p><strong>测试日期:</strong> {date}</p>
    </div>
"""
        
        if self._include_summary.isChecked():
            html += """
    <h2>执行摘要</h2>
    <p>本次安全测试针对目标系统进行了全面的安全评估，发现了若干安全隐患。</p>
"""
        
        if self._include_scope.isChecked():
            html += f"""
    <h2>测试范围</h2>
    <ul>
        <li>目标: {target}</li>
        <li>测试类型: Web应用安全测试</li>
    </ul>
"""
        
        if self._include_vulns.isChecked():
            html += """
    <h2>漏洞详情</h2>
    <div class="vuln high">
        <h3>SQL注入漏洞</h3>
        <p><strong>危害等级:</strong> 高危</p>
        <p><strong>影响:</strong> 可能导致数据库信息泄露</p>
    </div>
    <div class="vuln medium">
        <h3>XSS跨站脚本</h3>
        <p><strong>危害等级:</strong> 中危</p>
        <p><strong>影响:</strong> 可能导致用户信息被窃取</p>
    </div>
"""
        
        if self._include_remediation.isChecked():
            html += """
    <h2>修复建议</h2>
    <ol>
        <li>对所有用户输入进行严格的过滤和验证</li>
        <li>使用参数化查询防止SQL注入</li>
        <li>对输出进行HTML编码防止XSS攻击</li>
    </ol>
"""
        
        html += """
</body>
</html>"""
        return html
    
    def _build_md_report(self, project: str, target: str, tester: str, date: str) -> str:
        md = f"""# 安全测试报告

## 基本信息

- **项目名称:** {project}
- **目标地址:** {target}
- **测试人员:** {tester}
- **测试日期:** {date}

"""
        if self._include_summary.isChecked():
            md += """## 执行摘要

本次安全测试针对目标系统进行了全面的安全评估。

"""
        if self._include_vulns.isChecked():
            md += """## 漏洞详情

### SQL注入漏洞
- **危害等级:** 高危
- **影响:** 数据库信息泄露

### XSS跨站脚本
- **危害等级:** 中危
- **影响:** 用户信息窃取

"""
        return md
    
    def _build_json_report(self, project: str, target: str, tester: str, date: str) -> str:
        report = {
            "project": project,
            "target": target,
            "tester": tester,
            "date": date,
            "vulnerabilities": [
                {"name": "SQL注入", "severity": "高", "status": "未修复"},
                {"name": "XSS", "severity": "中", "status": "未修复"}
            ]
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def _build_pdf_report(self, project: str, target: str, tester: str, date: str) -> str:
        html_content = self._build_html_report(project, target, tester, date)
        pdf_content = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 200 >>
stream
BT
/F1 12 Tf
50 750 Td
(安全测试报告) Tj
0 -20 Td
(项目: {project}) Tj
0 -15 Td
(目标: {target}) Tj
0 -15 Td
(测试人员: {tester}) Tj
0 -15 Td
(日期: {date}) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
0000000518 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
597
%%EOF"""
        return pdf_content
    
    def _build_doc_report(self, project: str, target: str, tester: str, date: str) -> str:
        doc_content = f"""<html xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:w="urn:schemas-microsoft-com:office:word"
xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="UTF-8">
<title>安全测试报告 - {project}</title>
<style>
body {{ font-family: "Microsoft YaHei", Arial, sans-serif; margin: 40px; }}
h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; font-size: 24pt; }}
h2 {{ color: #007bff; margin-top: 30px; font-size: 18pt; }}
h3 {{ color: #333; font-size: 14pt; }}
.info {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
.vuln {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
.high {{ border-left: 4px solid #dc3545; }}
.medium {{ border-left: 4px solid #ffc107; }}
.low {{ border-left: 4px solid #28a745; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f5f5f5; }}
</style>
</head>
<body>
<h1>安全测试报告</h1>
<div class="info">
<p><strong>项目名称:</strong> {project}</p>
<p><strong>目标地址:</strong> {target}</p>
<p><strong>测试人员:</strong> {tester}</p>
<p><strong>测试日期:</strong> {date}</p>
</div>
"""
        if self._include_summary.isChecked():
            doc_content += """
<h2>执行摘要</h2>
<p>本次安全测试针对目标系统进行了全面的安全评估，发现了若干安全隐患。建议尽快修复发现的漏洞，以确保系统安全。</p>
"""
        if self._include_scope.isChecked():
            doc_content += f"""
<h2>测试范围</h2>
<table>
<tr><th>项目</th><th>内容</th></tr>
<tr><td>目标</td><td>{target}</td></tr>
<tr><td>测试类型</td><td>Web应用安全测试</td></tr>
<tr><td>测试方法</td><td>黑盒测试、灰盒测试</td></tr>
</table>
"""
        if self._include_vulns.isChecked():
            doc_content += """
<h2>漏洞详情</h2>
<div class="vuln high">
<h3>SQL注入漏洞</h3>
<p><strong>危害等级:</strong> 高危</p>
<p><strong>漏洞描述:</strong> 在登录页面发现SQL注入漏洞，攻击者可通过构造恶意SQL语句获取数据库敏感信息。</p>
<p><strong>影响:</strong> 可能导致数据库信息泄露、数据篡改或删除</p>
</div>
<div class="vuln medium">
<h3>XSS跨站脚本</h3>
<p><strong>危害等级:</strong> 中危</p>
<p><strong>漏洞描述:</strong> 在搜索功能发现反射型XSS漏洞，攻击者可注入恶意脚本。</p>
<p><strong>影响:</strong> 可能导致用户信息被窃取、会话劫持</p>
</div>
"""
        if self._include_remediation.isChecked():
            doc_content += """
<h2>修复建议</h2>
<ol>
<li><strong>SQL注入:</strong> 使用参数化查询，对所有用户输入进行严格过滤和验证</li>
<li><strong>XSS:</strong> 对所有输出进行HTML编码，实施内容安全策略(CSP)</li>
<li>定期进行安全代码审计和渗透测试</li>
<li>及时更新和修补系统组件</li>
</ol>
"""
        doc_content += """
<h2>总结</h2>
<p>本次安全测试共发现若干安全问题，建议按照优先级进行修复。如有疑问，请联系测试团队。</p>
</body>
</html>"""
        return doc_content
    
    def _preview_report(self):
        project = self._project_name.text() or "未命名项目"
        target = self._target_input.text() or "未指定"
        tester = self._tester_input.text() or "匿名"
        date = self._date_edit.date().toString("yyyy-MM-dd")
        
        report = self._build_report(project, target, tester, date)
        
        preview_dialog = QDialog(self)
        preview_dialog.setWindowTitle("报告预览")
        preview_dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(preview_dialog)
        
        preview_text = QPlainTextEdit()
        preview_text.setPlainText(report)
        preview_text.setReadOnly(True)
        layout.addWidget(preview_text)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(preview_dialog.accept)
        layout.addWidget(close_btn)
        
        preview_dialog.exec()
    
    def _do_scan(self):
        self._generate_report()


@register_module("project_manage")
class ProjectManageWidget(BaseModuleWidget):
    def __init__(self):
        self._projects = {}
        self._load_projects()
        super().__init__("项目管理")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        toolbar_layout = QHBoxLayout()
        
        new_btn = QPushButton("新建项目")
        new_btn.clicked.connect(self._new_project)
        
        open_btn = QPushButton("打开项目")
        open_btn.clicked.connect(self._open_project)
        
        save_btn = QPushButton("保存项目")
        save_btn.clicked.connect(self._save_project)
        
        export_btn = QPushButton("导出项目")
        export_btn.clicked.connect(self._export_project)
        
        toolbar_layout.addWidget(new_btn)
        toolbar_layout.addWidget(open_btn)
        toolbar_layout.addWidget(save_btn)
        toolbar_layout.addWidget(export_btn)
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)
        
        self._project_tree = QTreeWidget()
        self._project_tree.setHeaderLabels(["项目", "创建时间", "状态"])
        self._project_tree.setColumnWidth(0, 200)
        layout.addWidget(self._project_tree)
        
        details_group = QGroupBox("项目详情")
        details_layout = QFormLayout(details_group)
        
        self._proj_name = QLineEdit()
        details_layout.addRow("项目名称:", self._proj_name)
        
        self._proj_target = QLineEdit()
        details_layout.addRow("目标:", self._proj_target)
        
        self._proj_status = QComboBox()
        self._setup_combo(self._proj_status, ["进行中", "已完成", "暂停", "待审核"])
        details_layout.addRow("状态:", self._proj_status)
        
        self._proj_notes = QTextEdit()
        self._proj_notes.setMaximumHeight(100)
        details_layout.addRow("备注:", self._proj_notes)
        
        layout.addWidget(details_group)
        
        self._project_tree.itemClicked.connect(self._select_project)
        
        self._refresh_tree()
        
        return widget
    
    def _load_projects(self):
        config_path = Path("config/projects.json")
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                self._projects = json.load(f)
    
    def _save_projects_config(self):
        config_path = Path("config/projects.json")
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(self._projects, f, indent=2, ensure_ascii=False)
    
    def _refresh_tree(self):
        self._project_tree.clear()
        for proj_id, proj in self._projects.items():
            item = QTreeWidgetItem([
                proj.get("name", proj_id),
                proj.get("created", "-"),
                proj.get("status", "进行中")
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, proj_id)
            self._project_tree.addTopLevelItem(item)
    
    def _new_project(self):
        proj_id = f"proj_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self._projects[proj_id] = {
            "name": "新项目",
            "target": "",
            "status": "进行中",
            "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "notes": "",
            "results": []
        }
        self._save_projects_config()
        self._refresh_tree()
        self._add_log(LogLevel.SUCCESS, "已创建新项目")
    
    def _open_project(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开项目", "", "JSON文件 (*.json);;所有文件 (*)"
        )
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as f:
                proj = json.load(f)
            proj_id = Path(file_path).stem
            self._projects[proj_id] = proj
            self._save_projects_config()
            self._refresh_tree()
            self._add_log(LogLevel.SUCCESS, f"已打开项目: {proj.get('name', proj_id)}")
    
    def _save_project(self):
        selected = self._project_tree.currentItem()
        if not selected:
            self._add_log(LogLevel.WARNING, "请先选择项目")
            return
        
        proj_id = selected.data(0, Qt.ItemDataRole.UserRole)
        if proj_id in self._projects:
            self._projects[proj_id]["name"] = self._proj_name.text()
            self._projects[proj_id]["target"] = self._proj_target.text()
            self._projects[proj_id]["status"] = self._proj_status.currentText()
            self._projects[proj_id]["notes"] = self._proj_notes.toPlainText()
            
            self._save_projects_config()
            self._refresh_tree()
            self._add_log(LogLevel.SUCCESS, "项目已保存")
    
    def _export_project(self):
        selected = self._project_tree.currentItem()
        if not selected:
            self._add_log(LogLevel.WARNING, "请先选择项目")
            return
        
        proj_id = selected.data(0, Qt.ItemDataRole.UserRole)
        if proj_id in self._projects:
            proj = self._projects[proj_id]
            file_path, _ = QFileDialog.getSaveFileName(
                self, "导出项目", f"{proj.get('name', proj_id)}.json",
                "JSON文件 (*.json);;所有文件 (*)"
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(proj, f, indent=2, ensure_ascii=False)
                self._add_log(LogLevel.SUCCESS, f"项目已导出: {file_path}")
    
    def _select_project(self, item: QTreeWidgetItem):
        proj_id = item.data(0, Qt.ItemDataRole.UserRole)
        if proj_id in self._projects:
            proj = self._projects[proj_id]
            self._proj_name.setText(proj.get("name", ""))
            self._proj_target.setText(proj.get("target", ""))
            self._proj_status.setCurrentText(proj.get("status", "进行中"))
            self._proj_notes.setPlainText(proj.get("notes", ""))
    
    def _do_scan(self):
        self._add_log(LogLevel.INFO, "使用上方按钮管理项目")


@register_module("data_export")
class DataExportWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("数据导出")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        source_group = QGroupBox("数据源")
        source_layout = QVBoxLayout(source_group)
        
        self._source_combo = QComboBox()
        self._setup_combo(self._source_combo, [
            "扫描结果", "漏洞列表", "资产清单", "字典数据", "日志记录"
        ])
        source_layout.addWidget(QLabel("选择数据源:"))
        source_layout.addWidget(self._source_combo)
        
        layout.addWidget(source_group)
        
        format_group = QGroupBox("导出格式")
        format_layout = QVBoxLayout(format_group)
        
        self._format_group = QButtonGroup()
        formats = [
            ("CSV", True), 
            ("JSON", False), 
            ("Excel (.xlsx)", False), 
            ("XML", False), 
            ("HTML", False), 
            ("Markdown (.md)", False), 
            ("PDF", False), 
            ("Word (.doc)", False)
        ]
        
        for i, (fmt, checked) in enumerate(formats):
            rb = QRadioButton(fmt)
            rb.setChecked(checked)
            self._format_group.addButton(rb, i)
            format_layout.addWidget(rb)
        
        layout.addWidget(format_group)
        
        options_group = QGroupBox("导出选项")
        options_layout = QVBoxLayout(options_group)
        
        self._include_header = QCheckBox("包含表头")
        self._include_header.setChecked(True)
        options_layout.addWidget(self._include_header)
        
        self._pretty_print = QCheckBox("美化输出")
        self._pretty_print.setChecked(True)
        options_layout.addWidget(self._pretty_print)
        
        self._timestamp_name = QCheckBox("文件名添加时间戳")
        self._timestamp_name.setChecked(True)
        options_layout.addWidget(self._timestamp_name)
        
        layout.addWidget(options_group)
        
        btn_layout = QHBoxLayout()
        
        export_btn = QPushButton("导出数据")
        export_btn.clicked.connect(self._export_data)
        
        preview_btn = QPushButton("预览数据")
        preview_btn.setObjectName("secondaryButton")
        preview_btn.clicked.connect(self._preview_data)
        
        btn_layout.addWidget(export_btn)
        btn_layout.addWidget(preview_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        return widget
    
    def _export_data(self):
        source = self._source_combo.currentText()
        format_id = self._format_group.checkedId()
        formats = ["csv", "json", "xlsx", "xml", "html", "md", "pdf", "doc"]
        fmt = formats[format_id] if format_id >= 0 else "csv"
        
        sample_data = self._get_sample_data(source)
        
        ext_map = {"csv": "csv", "json": "json", "xlsx": "xlsx", "xml": "xml", "html": "html", "md": "md", "pdf": "pdf", "doc": "doc"}
        filter_map = {
            "csv": "CSV 文件 (*.csv)",
            "json": "JSON 文件 (*.json)",
            "xlsx": "Excel 文件 (*.xlsx)",
            "xml": "XML 文件 (*.xml)",
            "html": "HTML 文件 (*.html)",
            "md": "Markdown 文件 (*.md)",
            "pdf": "PDF 文件 (*.pdf)",
            "doc": "Word 文件 (*.doc)"
        }
        timestamp = datetime.now().strftime("_%Y%m%d_%H%M%S") if self._timestamp_name.isChecked() else ""
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出数据", f"{source}{timestamp}.{ext_map.get(fmt, 'csv')}",
            f"{filter_map.get(fmt, 'CSV 文件 (*.csv)')}"
        )
        
        if file_path:
            content = self._format_data(sample_data, fmt)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._add_log(LogLevel.SUCCESS, f"数据已导出: {file_path}")
            self._add_result(source, fmt.upper(), "导出完成", f"{len(sample_data)} 条记录")
    
    def _get_sample_data(self, source: str) -> List[Dict]:
        return [
            {"id": 1, "target": "example.com", "status": "完成", "result": "发现漏洞"},
            {"id": 2, "target": "test.com", "status": "进行中", "result": "扫描中"},
            {"id": 3, "target": "demo.com", "status": "完成", "result": "无漏洞"},
        ]
    
    def _format_data(self, data: List[Dict], fmt: str) -> str:
        if fmt == "json":
            indent = 2 if self._pretty_print.isChecked() else None
            return json.dumps(data, indent=indent, ensure_ascii=False)
        
        elif fmt == "csv":
            lines = []
            if data and self._include_header.isChecked():
                lines.append(','.join(data[0].keys()))
            for row in data:
                lines.append(','.join(str(v) for v in row.values()))
            return '\n'.join(lines)
        
        elif fmt == "xml":
            xml = '<?xml version="1.0" encoding="UTF-8"?>\n<data>\n'
            for row in data:
                xml += '  <record>\n'
                for k, v in row.items():
                    xml += f'    <{k}>{v}</{k}>\n'
                xml += '  </record>\n'
            xml += '</data>'
            return xml
        
        elif fmt == "html":
            html = '<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8">\n<title>数据导出</title>\n'
            html += '<style>table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f5f5f5}</style>\n'
            html += '</head>\n<body>\n<table>\n'
            if data and self._include_header.isChecked():
                html += '<tr>' + ''.join(f'<th>{k}</th>' for k in data[0].keys()) + '</tr>\n'
            for row in data:
                html += '<tr>' + ''.join(f'<td>{v}</td>' for v in row.values()) + '</tr>\n'
            html += '</table>\n</body>\n</html>'
            return html
        
        elif fmt == "md":
            md = "# 数据导出\n\n"
            if data:
                headers = list(data[0].keys())
                md += "| " + " | ".join(headers) + " |\n"
                md += "| " + " | ".join(["---"] * len(headers)) + " |\n"
                for row in data:
                    md += "| " + " | ".join(str(v) for v in row.values()) + " |\n"
            return md
        
        elif fmt == "pdf":
            pdf = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 300 >>
stream
BT
/F1 12 Tf
50 750 Td
(数据导出报告) Tj
0 -20 Td
({len(data)} 条记录) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
0000000618 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
697
%%EOF"""
            return pdf
        
        elif fmt == "doc":
            doc = f"""<html xmlns:o="urn:schemas-microsoft-com:office:office"
xmlns:w="urn:schemas-microsoft-com:office:word"
xmlns="http://www.w3.org/TR/REC-html40">
<head>
<meta charset="UTF-8">
<title>数据导出</title>
<style>
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #000;padding:8px}}
th{{background:#f0f0f0}}
</style>
</head>
<body>
<h1>数据导出</h1>
<p>共 {len(data)} 条记录</p>
<table>
"""
            if data and self._include_header.isChecked():
                doc += '<tr>' + ''.join(f'<th>{k}</th>' for k in data[0].keys()) + '</tr>\n'
            for row in data:
                doc += '<tr>' + ''.join(f'<td>{v}</td>' for v in row.values()) + '</tr>\n'
            doc += '</table>\n</body>\n</html>'
            return doc
        
        elif fmt == "xlsx":
            return self._format_xlsx(data)
        
        return str(data)
    
    def _format_xlsx(self, data: List[Dict]) -> str:
        lines = []
        if data and self._include_header.isChecked():
            lines.append('\t'.join(data[0].keys()))
        for row in data:
            lines.append('\t'.join(str(v) for v in row.values()))
        return '\n'.join(lines)
    
    def _preview_data(self):
        source = self._source_combo.currentText()
        data = self._get_sample_data(source)
        
        preview_dialog = QDialog(self)
        preview_dialog.setWindowTitle(f"数据预览 - {source}")
        preview_dialog.setMinimumSize(500, 300)
        
        layout = QVBoxLayout(preview_dialog)
        
        table = QTableWidget()
        if data:
            table.setColumnCount(len(data[0]))
            table.setHorizontalHeaderLabels(data[0].keys())
            table.setRowCount(len(data))
            for i, row in enumerate(data):
                for j, v in enumerate(row.values()):
                    table.setItem(i, j, QTableWidgetItem(str(v)))
        layout.addWidget(table)
        
        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(preview_dialog.accept)
        layout.addWidget(close_btn)
        
        preview_dialog.exec()
    
    def _do_scan(self):
        self._export_data()


@register_module("vuln_stats")
class VulnStatsWidget(BaseModuleWidget):
    def __init__(self):
        super().__init__("漏洞统计")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        filter_group = QGroupBox("筛选条件")
        filter_layout = QFormLayout(filter_group)
        
        self._project_combo = QComboBox()
        self._setup_combo(self._project_combo, ["全部项目", "项目A", "项目B", "项目C"])
        filter_layout.addRow("项目:", self._project_combo)
        
        self._severity_combo = QComboBox()
        self._setup_combo(self._severity_combo, ["全部等级", "严重", "高危", "中危", "低危", "信息"])
        filter_layout.addRow("等级:", self._severity_combo)
        
        self._status_combo = QComboBox()
        self._setup_combo(self._status_combo, ["全部状态", "未修复", "修复中", "已修复", "忽略"])
        filter_layout.addRow("状态:", self._status_combo)
        
        layout.addWidget(filter_group)
        
        stats_btn = QPushButton("生成统计")
        stats_btn.clicked.connect(self._generate_stats)
        layout.addWidget(stats_btn)
        
        summary_group = QGroupBox("统计概览")
        summary_layout = QFormLayout(summary_group)
        
        self._total_label = QLabel("0")
        summary_layout.addRow("漏洞总数:", self._total_label)
        
        self._critical_label = QLabel("0")
        summary_layout.addRow("严重:", self._critical_label)
        
        self._high_label = QLabel("0")
        summary_layout.addRow("高危:", self._high_label)
        
        self._medium_label = QLabel("0")
        summary_layout.addRow("中危:", self._medium_label)
        
        self._low_label = QLabel("0")
        summary_layout.addRow("低危:", self._low_label)
        
        self._fixed_label = QLabel("0")
        summary_layout.addRow("已修复:", self._fixed_label)
        
        layout.addWidget(summary_group)
        
        self._stats_table = QTableWidget()
        self._stats_table.setColumnCount(5)
        self._stats_table.setHorizontalHeaderLabels(["漏洞名称", "等级", "状态", "数量", "占比"])
        self._stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self._stats_table)
        
        return widget
    
    def _generate_stats(self):
        vulns = [
            {"name": "SQL注入", "severity": "高危", "status": "未修复", "count": 3},
            {"name": "XSS", "severity": "中危", "status": "修复中", "count": 5},
            {"name": "CSRF", "severity": "中危", "status": "已修复", "count": 2},
            {"name": "信息泄露", "severity": "低危", "status": "未修复", "count": 8},
            {"name": "弱密码", "severity": "高危", "status": "未修复", "count": 4},
            {"name": "目录遍历", "severity": "中危", "status": "忽略", "count": 1},
            {"name": "RCE", "severity": "严重", "status": "已修复", "count": 1},
        ]
        
        total = sum(v["count"] for v in vulns)
        critical = sum(v["count"] for v in vulns if v["severity"] == "严重")
        high = sum(v["count"] for v in vulns if v["severity"] == "高危")
        medium = sum(v["count"] for v in vulns if v["severity"] == "中危")
        low = sum(v["count"] for v in vulns if v["severity"] == "低危")
        fixed = sum(v["count"] for v in vulns if v["status"] == "已修复")
        
        self._total_label.setText(str(total))
        self._critical_label.setText(str(critical))
        self._high_label.setText(str(high))
        self._medium_label.setText(str(medium))
        self._low_label.setText(str(low))
        self._fixed_label.setText(str(fixed))
        
        self._stats_table.setRowCount(len(vulns))
        for i, v in enumerate(vulns):
            self._stats_table.setItem(i, 0, QTableWidgetItem(v["name"]))
            self._stats_table.setItem(i, 1, QTableWidgetItem(v["severity"]))
            self._stats_table.setItem(i, 2, QTableWidgetItem(v["status"]))
            self._stats_table.setItem(i, 3, QTableWidgetItem(str(v["count"])))
            self._stats_table.setItem(i, 4, QTableWidgetItem(f"{v['count']/total*100:.1f}%"))
        
        self._add_log(LogLevel.SUCCESS, f"统计完成: 共 {total} 个漏洞")
        self._add_result("漏洞统计", f"{total}个", "完成", f"高危: {high}, 中危: {medium}")
    
    def _do_scan(self):
        self._generate_stats()


@register_module("history")
class HistoryWidget(BaseModuleWidget):
    def __init__(self):
        self._history = []
        super().__init__("历史记录")
    
    def _create_options_widget(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        toolbar_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self._refresh_history)
        
        clear_btn = QPushButton("清空历史")
        clear_btn.setObjectName("dangerButton")
        clear_btn.clicked.connect(self._clear_history)
        
        export_btn = QPushButton("导出历史")
        export_btn.clicked.connect(self._export_history)
        
        toolbar_layout.addWidget(refresh_btn)
        toolbar_layout.addWidget(clear_btn)
        toolbar_layout.addWidget(export_btn)
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)
        
        filter_group = QGroupBox("筛选")
        filter_layout = QHBoxLayout(filter_group)
        
        filter_layout.addWidget(QLabel("类型:"))
        self._type_combo = QComboBox()
        self._setup_combo(self._type_combo, ["全部", "扫描", "生成", "导出", "其他"])
        self._type_combo.currentTextChanged.connect(self._filter_history)
        filter_layout.addWidget(self._type_combo)
        
        filter_layout.addWidget(QLabel("搜索:"))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("关键词搜索")
        self._search_input.textChanged.connect(self._filter_history)
        filter_layout.addWidget(self._search_input)
        
        layout.addWidget(filter_group)
        
        self._history_table = QTableWidget()
        self._history_table.setColumnCount(5)
        self._history_table.setHorizontalHeaderLabels(["时间", "类型", "模块", "目标", "结果"])
        self._history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._history_table)
        
        detail_group = QGroupBox("详情")
        detail_layout = QVBoxLayout(detail_group)
        
        self._detail_text = QPlainTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setMaximumHeight(100)
        detail_layout.addWidget(self._detail_text)
        
        self._history_table.itemClicked.connect(self._show_detail)
        
        layout.addWidget(detail_group)
        
        self._load_history()
        
        return widget
    
    def _load_history(self):
        history_path = Path("config/history.json")
        if history_path.exists():
            with open(history_path, 'r', encoding='utf-8') as f:
                self._history = json.load(f)
        else:
            self._history = [
                {"time": "2024-01-15 10:30:00", "type": "扫描", "module": "端口扫描", "target": "example.com", "result": "完成", "detail": "发现开放端口: 80, 443, 22"},
                {"time": "2024-01-15 11:00:00", "type": "生成", "module": "密码生成", "target": "-", "result": "完成", "detail": "生成100个随机密码"},
                {"time": "2024-01-15 14:20:00", "type": "扫描", "module": "漏洞扫描", "target": "test.com", "result": "发现漏洞", "detail": "发现SQL注入漏洞"},
            ]
    
    def _save_history(self):
        history_path = Path("config/history.json")
        history_path.parent.mkdir(parents=True, exist_ok=True)
        with open(history_path, 'w', encoding='utf-8') as f:
            json.dump(self._history, f, indent=2, ensure_ascii=False)
    
    def _refresh_history(self):
        self._filter_history()
    
    def _filter_history(self):
        type_filter = self._type_combo.currentText()
        search = self._search_input.text().lower()
        
        filtered = []
        for h in self._history:
            if type_filter != "全部" and h.get("type") != type_filter:
                continue
            if search and search not in json.dumps(h, ensure_ascii=False).lower():
                continue
            filtered.append(h)
        
        self._history_table.setRowCount(len(filtered))
        for i, h in enumerate(filtered):
            self._history_table.setItem(i, 0, QTableWidgetItem(h.get("time", "-")))
            self._history_table.setItem(i, 1, QTableWidgetItem(h.get("type", "-")))
            self._history_table.setItem(i, 2, QTableWidgetItem(h.get("module", "-")))
            self._history_table.setItem(i, 3, QTableWidgetItem(h.get("target", "-")))
            self._history_table.setItem(i, 4, QTableWidgetItem(h.get("result", "-")))
            self._history_table.item(i, 0).setData(Qt.ItemDataRole.UserRole, h)
        
        self._add_log(LogLevel.INFO, f"显示 {len(filtered)} 条记录")
    
    def _show_detail(self, item: QTableWidgetItem):
        h = item.data(Qt.ItemDataRole.UserRole)
        if h:
            self._detail_text.setPlainText(h.get("detail", "无详情"))
    
    def _clear_history(self):
        reply = QMessageBox.question(self, "确认清空", "确定要清空所有历史记录吗？",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._history.clear()
            self._save_history()
            self._history_table.setRowCount(0)
            self._add_log(LogLevel.SUCCESS, "历史记录已清空")
    
    def _export_history(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出历史", "", "JSON文件 (*.json);;CSV文件 (*.csv);;所有文件 (*)"
        )
        
        if file_path:
            if file_path.endswith('.csv'):
                lines = ['time,type,module,target,result']
                for h in self._history:
                    lines.append(f"{h.get('time')},{h.get('type')},{h.get('module')},{h.get('target')},{h.get('result')}")
                content = '\n'.join(lines)
            else:
                content = json.dumps(self._history, indent=2, ensure_ascii=False)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            self._add_log(LogLevel.SUCCESS, f"历史已导出: {file_path}")
    
    def _do_scan(self):
        self._refresh_history()
