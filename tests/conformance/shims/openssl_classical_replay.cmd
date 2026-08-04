@echo off
rem SPDX-FileCopyrightText: 2026 BreachSAFE
rem SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
python "%~dp0..\..\fixtures\openssl\fake\fake_openssl_script" openssl_classical_replay %*
