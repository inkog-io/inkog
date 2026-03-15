# CI/CD Integration Guide

Integrate Inkog into your CI/CD pipelines to ensure automated security and logic checks on every commit or merge request. All our CI/CD templates produce SARIF files, enabling native integration with your platform's security dashboards.

## GitHub Actions

Use the official Inkog GitHub Action:

```yaml
name: Inkog Security Scan
on:
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Inkog Scan
        uses: inkog-io/inkog@v1
        with:
          api-key: ${{ secrets.INKOG_API_KEY }}
          sarif-upload: true
          policy: balanced
          severity: low
          path: .
```

## GitLab CI

GitLab has native SARIF support in its Security Dashboard. You can upload Inkog's SARIF output as a SAST report artifact.
Add the following to your `.gitlab-ci.yml`:

> **Note:** Ensure you add `INKOG_API_KEY` as a masked variable in your GitLab CI/CD Settings!

```yaml
variables:
  INKOG_POLICY: "balanced"
  INKOG_PATH: "."
  INKOG_SEVERITY: "low"

inkog-scan:
  stage: test
  image: ghcr.io/inkog-io/inkog:latest
  script:
    - inkog -path $INKOG_PATH -policy $INKOG_POLICY -severity $INKOG_SEVERITY -output sarif > gl-inkog-results.sarif
  artifacts:
    reports:
      sast: gl-inkog-results.sarif
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

## Azure DevOps

Azure DevOps can view SARIF files using the [SARIF viewer extension](https://marketplace.visualstudio.com/items?itemName=sariftools.scans).
Add this task to your `azure-pipelines.yml`:

> **Note:** Map your `INKOG_API_KEY` secret variable to the environment variable!

```yaml
variables:
  INKOG_POLICY: 'balanced'
  INKOG_PATH: '$(Build.SourcesDirectory)'
  INKOG_SEVERITY: 'low'

steps:
- task: Bash@3
  displayName: 'Inkog Security Scan'
  inputs:
    targetType: 'inline'
    script: |
      curl -fsSL https://get.inkog.io | sh
      inkog -path $(INKOG_PATH) -policy $(INKOG_POLICY) -severity $(INKOG_SEVERITY) -output sarif > $(Build.ArtifactStagingDirectory)/inkog.sarif
  env:
    INKOG_API_KEY: $(INKOG_API_KEY)
```

## Jenkins

For Jenkins, use the Warnings Next Generation plugin to read SARIF output.
Add the following stage to your `Jenkinsfile`:

> **Note:** Make sure you have added your Inkog API key to your Jenkins credentials.

```groovy
pipeline {
    agent any
    environment {
        INKOG_API_KEY = credentials('inkog-api-key')
        INKOG_POLICY = 'balanced'
        INKOG_PATH = '.'
        INKOG_SEVERITY = 'low'
    }
    stages {
        stage('Inkog Security Scan') {
            steps {
                sh 'curl -fsSL https://get.inkog.io | sh'
                sh 'inkog -path ${INKOG_PATH} -policy ${INKOG_POLICY} -severity ${INKOG_SEVERITY} -output sarif > inkog-results.sarif'
            }
        }
    }
    post {
        always {
            recordIssues(tools: [sarif(pattern: 'inkog-results.sarif')])
        }
    }
}
```
