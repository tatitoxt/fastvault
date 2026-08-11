name: Bug Report
description: Create a report to help us improve FastVault
title: "[BUG] "
labels: ["bug"]
body:
  - type: textarea
    id: description
    attributes:
      label: Bug Description
      description: A clear description of what the bug is.
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: Steps to reproduce the behavior.
      placeholder: |
        1. fastvault init
        2. fastvault set prod/db
        3. See error
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: FastVault Version
      placeholder: "e.g. 0.1.0"
    validations:
      required: true
  - type: textarea
    id: environment
    attributes:
      label: OS / Environment
      placeholder: "e.g. macOS 14.5 Sonoma / Ubuntu 22.04 LTS"
    validations:
      required: true
