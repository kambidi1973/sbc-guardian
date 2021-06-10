# SBC Guardian

[![Build Status](https://img.shields.io/github/actions/workflow/status/kambidi1973/sbc-guardian/ci.yml?branch=main)](https://github.com/kambidi1973/sbc-guardian/actions)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-teal.svg)](https://fastapi.tiangolo.com)

Centralized **Session Border Controller management and monitoring platform** for multi-vendor SBC fleets (Oracle/ACME, AudioCodes, Cisco CUBE). Real-time analytics, config versioning, SIP traffic analytics, capacity planning, and security auditing.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     SBC Guardian                          │
│                                                          │
│  ┌───────────────┐     ┌──────────────────────────────┐  │
│  │ React Dashboard│◄──►│ FastAPI Backend               │  │
│  │               │     │ • Device Mgmt • Config Ctrl   │  │
│  │ • Status      │     │ • SIP Analytics • Security    │  │
│  │ • Charts      │     │ • Capacity Planning           │  │
│  │ • Alerts      │     └──────────┬───────────────────┘  │
│  └───────────────┘                │                      │
│  ┌────────────────────────────────▼──────────────────┐   │
│  │              SBC Connectors                        │   │
│  │  ┌────────┐  ┌────────────┐  ┌──────────────┐    │   │
│  │  │ ACME/  │  │ AudioCodes │  │ Cisco CUBE   │    │   │
│  │  │ Oracle │  │            │  │              │    │   │
│  │  └────────┘  └────────────┘  └──────────────┘    │   │
│  └───────────────────────────────────────────────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐     │
│  │  SNMP    │  │ Ansible  │  │ Prometheus Export  │     │
│  └──────────┘  └──────────┘  └────────────────────┘     │
└──────────────────────────────────────────────────────────┘
```

## Features

- **Multi-vendor Support** — Oracle/ACME SBC, AudioCodes, Cisco CUBE
- **Config Versioning** — Git-like config management with diff and rollback
- **SIP Analytics** — CPS, ASR, ACD, NER, trunk utilization, codec distribution
- **Security Audit** — TLS certificate monitoring, ACL management, topology hiding validation
- **Capacity Planning** — Historical trending, predictive forecasting, threshold alerting
- **Ansible IaC** — Fleet-wide configuration deployment automation

## Quick Start

```bash
git clone https://github.com/kambidi1973/sbc-guardian.git && cd sbc-guardian
docker-compose up -d
# Dashboard: http://localhost:3000 | API: http://localhost:8000/docs
```

## Tech Stack

Python/FastAPI | React/TypeScript | PostgreSQL | Prometheus/Grafana | Ansible | Docker

## Author

**Gopala Rao Kambidi** — Senior Technology Architect with extensive SBC deployment and management experience.
