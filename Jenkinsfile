// ============================================================
// Jenkinsfile — DevSecOps CI Pipeline
// Capstone Project: DevSecOps + GitOps for Microservices on AWS
// ============================================================

pipeline {
    agent any

    environment {
        // AWS & ECR
        AWS_REGION             = 'ap-southeast-1'
        AWS_ACCOUNT_ID         = '758346258990'
        ECR_BASE_URL           = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        ENVIRONMENT_NAME       = 'uit-devsecops-dev'

        // Git repos
        APP_REPO_URL           = 'https://github.com/min-hit-1701/retail-store-app.git'
        GITOPS_REPO_URL        = 'https://github.com/min-hit-1701/retail-store-gitops.git'
        GITOPS_REPO_PATH       = '/tmp/gitops-repo'

        // Services to build (comma-separated, handled in loop)
        SERVICES               = 'ui,cart,orders,catalog,checkout'

        // SonarQube
        SONAR_HOST_URL         = 'http://sonarqube:9000'
        SONAR_PROJECT_KEY      = 'uit-devsecops-retail-store'

        // OWASP Dependency Check
        OWASP_NVD_API_KEY      = credentials('OWASP_NVD_API_KEY')

        // Image tag based on git commit short SHA
        IMAGE_TAG              = "${env.GIT_COMMIT ? env.GIT_COMMIT.take(7) : 'latest'}"

        // Trivy severity threshold
        TRIVY_SEVERITY         = 'CRITICAL,HIGH'
    }

    parameters {
        string(name: 'GIT_BRANCH', defaultValue: 'main', description: 'Branch to build')
        string(name: 'IMAGE_TAG_OVERRIDE', defaultValue: '', description: 'Override image tag (leave empty for git SHA)')
    }

    stages {

        // ------------------------------------------------------------------
        // Stage 1: Checkout
        // ------------------------------------------------------------------
        stage('Checkout') {
            steps {
                script {
                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: "${params.GIT_BRANCH}"]],
                        userRemoteConfigs: [[url: "${env.APP_REPO_URL}"]]
                    ])

                    // Override image tag if parameter provided
                    if (params.IMAGE_TAG_OVERRIDE?.trim()) {
                        env.IMAGE_TAG = params.IMAGE_TAG_OVERRIDE.trim()
                    }

                    echo "Building branch: ${params.GIT_BRANCH}"
                    echo "Image tag: ${env.IMAGE_TAG}"
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 2: Build all services (parallel)
        // ------------------------------------------------------------------
        stage('Build') {
            steps {
                script {
                    def buildSteps = [:]
                    def services = env.SERVICES.split(',')

                    services.each { service ->
                        buildSteps[service] = {
                            dir("src/${service}") {
                                buildService(service.trim())
                            }
                        }
                    }

                    parallel buildSteps
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 3: SECURITY GATE 1 — SonarQube SAST
        // ------------------------------------------------------------------
        stage('SonarQube SAST') {
            steps {
                script {
                    echo "=== SECURITY GATE 1: SonarQube Static Analysis ==="

                    // Run SonarQube analysis
                    // SonarQube scanner reads sonar-project.properties in root
                    withSonarQubeEnv('SonarQube') {
                        sh '''
                            sonar-scanner \
                                -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                                -Dsonar.sources=src/ \
                                -Dsonar.java.binaries=src/*/target/ \
                                -Dsonar.language=java,go,typescript,javascript \
                                -Dsonar.projectName="Retail Store - DevSecOps" \
                                -Dsonar.projectVersion=${IMAGE_TAG}
                        '''
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 3b: SonarQube Quality Gate
        // ------------------------------------------------------------------
        stage('SonarQube Quality Gate') {
            steps {
                script {
                    timeout(time: 5, unit: 'MINUTES') {
                        def qg = waitForQualityGate()
                        if (qg.status != 'OK') {
                            error "SonarQube Quality Gate FAILED: ${qg.status}"
                        }
                        echo "SonarQube Quality Gate PASSED"
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 4: SECURITY GATE 2 — OWASP Dependency Check (SCA)
        // ------------------------------------------------------------------
        stage('OWASP Dependency Check') {
            steps {
                script {
                    echo "=== SECURITY GATE 2: OWASP Dependency Check ==="

                    sh '''
                        # Run OWASP Dependency Check
                        # Scans all dependency manifests in the project
                        /opt/dependency-check/bin/dependency-check.sh \
                            --scan src/ \
                            --format HTML \
                            --format JSON \
                            --out dependency-check-report \
                            --failOnCVSS 7 \
                            --nvdApiKey ${OWASP_NVD_API_KEY} \
                            || true  # Don't fail immediately, check report below

                        # Parse JSON report for HIGH/CRITICAL CVE count
                        HIGH_COUNT=$(python3 -c "
import json
with open('dependency-check-report/dependency-check-report.json') as f:
    data = json.load(f)
count = 0
for dep in data.get('dependencies', []):
    for vuln in dep.get('vulnerabilities', []):
        if vuln.get('cvssv3', {}).get('baseScore', 0) >= 7.0:
            count += 1
print(count)
                        ")

                        echo "OWASP DC: ${HIGH_COUNT} dependencies with CVSS >= 7.0"

                        if [ "${HIGH_COUNT}" -gt 0 ]; then
                            echo "OWASP Dependency Check found HIGH/CRITICAL vulnerabilities"
                            echo "Pipeline blocked by Security Gate 2"
                            exit 1
                        fi
                    '''
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 5: Docker Build all images (parallel)
        // ------------------------------------------------------------------
        stage('Docker Build') {
            steps {
                script {
                    // Login to ECR
                    sh '''
                        aws ecr get-login-password --region ${AWS_REGION} \
                            | docker login --username AWS --password-stdin ${ECR_BASE_URL}
                    '''

                    def buildSteps = [:]
                    def services = env.SERVICES.split(',')

                    services.each { service ->
                        def svc = service.trim()
                        def imageName = "${env.ECR_BASE_URL}/${env.ENVIRONMENT_NAME}-${svc}:${env.IMAGE_TAG}"
                        def dockerfilePath = "src/${svc}/Dockerfile"

                        buildSteps[svc] = {
                            script {
                                if (fileExists(dockerfilePath)) {
                                    sh "docker build -t ${imageName} -f ${dockerfilePath} src/${svc}/"
                                    sh "docker tag ${imageName} ${env.ECR_BASE_URL}/${env.ENVIRONMENT_NAME}-${svc}:latest"
                                    echo "Built: ${imageName}"
                                } else {
                                    error "Dockerfile not found: ${dockerfilePath}"
                                }
                            }
                        }
                    }

                    parallel buildSteps
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 6: SECURITY GATE 3 — Trivy Container Image Scan
        // ------------------------------------------------------------------
        stage('Trivy Image Scan') {
            steps {
                script {
                    echo "=== SECURITY GATE 3: Trivy Image Scan ==="

                    def scanSteps = [:]
                    def services = env.SERVICES.split(',')

                    services.each { service ->
                        def svc = service.trim()
                        def imageName = "${env.ECR_BASE_URL}/${env.ENVIRONMENT_NAME}-${svc}:${env.IMAGE_TAG}"

                        scanSteps[svc] = {
                            def result = sh(
                                script: """
                                    trivy image --severity ${TRIVY_SEVERITY} \
                                        --format json \
                                        --output trivy-report-${svc}.json \
                                        --exit-code 0 \
                                        ${imageName}

                                    # Check for CRITICAL vulnerabilities
                                    CRIT_COUNT=\$(python3 -c "
import json
with open('trivy-report-${svc}.json') as f:
    data = json.load(f)
count = sum(1 for r in data.get('Results', []) for v in r.get('Vulnerabilities', []) if v.get('Severity') == 'CRITICAL')
print(count)
                                    ")
                                    echo "${svc}: \${CRIT_COUNT} CRITICAL vulnerabilities"

                                    if [ "\${CRIT_COUNT}" -gt 0 ]; then
                                        echo "Trivy found CRITICAL vulnerabilities in ${svc}"
                                        exit 1
                                    fi
                                """,
                                returnStatus: true
                            )

                            if (result != 0) {
                                error "Image ${imageName} has CRITICAL vulnerabilities"
                            }
                        }
                    }

                    parallel scanSteps
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 7: Push to ECR
        // ------------------------------------------------------------------
        stage('Push to ECR') {
            steps {
                script {
                    echo "Pushing images to ECR..."

                    def pushSteps = [:]
                    def services = env.SERVICES.split(',')

                    services.each { service ->
                        def svc = service.trim()
                        def imageName = "${env.ECR_BASE_URL}/${env.ENVIRONMENT_NAME}-${svc}"

                        pushSteps[svc] = {
                            sh "docker push ${imageName}:${env.IMAGE_TAG}"
                            sh "docker push ${imageName}:latest"
                            echo "Pushed: ${imageName}:${env.IMAGE_TAG}"
                        }
                    }

                    parallel pushSteps
                }
            }
        }

        // ------------------------------------------------------------------
        // Stage 8: Update GitOps Repo
        // ------------------------------------------------------------------
        stage('Update GitOps Repo') {
            steps {
                script {
                    echo "Updating GitOps repo with new image tags..."

                    sshagent(['gitops-deploy-key']) {
                        sh '''
                            # Clone GitOps repo
                            git clone ${GITOPS_REPO_URL} ${GITOPS_REPO_PATH}
                            cd ${GITOPS_REPO_PATH}

                            # Update image tags in all overlay kustomization.yaml files
                            SERVICES="ui cart orders catalog checkout"
                            for svc in $SERVICES; do
                                IMAGE="${ECR_BASE_URL}/${ENVIRONMENT_NAME}-${svc}"
                                echo "Updating ${svc} to tag ${IMAGE_TAG}..."

                                # Find kustomization.yaml files and update newTag
                                find apps/ -name kustomization.yaml | while read f; do
                                    if grep -q "name: ${svc}" "$f" 2>/dev/null; then
                                        # Use sed to update newTag for the matching image
                                        python3 -c "
import yaml, sys
with open('${f}', 'r') as file:
    data = list(yaml.safe_load_all(file))
for doc in data:
    if doc and 'images' in doc:
        for img in doc['images']:
            if img.get('name') == '${svc}':
                img['newTag'] = '${IMAGE_TAG}'
with open('${f}', 'w') as file:
    yaml.dump_all(data, file)
                                        "
                                    fi
                                done
                            done

                            # Configure git and commit
                            git config user.email "ci-bot@devsecops.local"
                            git config user.name "CI Bot"

                            # Only commit if there are changes
                            if ! git diff --quiet; then
                                git add .
                                git commit -m "ci: update image tags to ${IMAGE_TAG} [skip ci]"
                                git push origin HEAD
                                echo "GitOps repo updated successfully"
                            else
                                echo "No changes to commit in GitOps repo"
                            fi
                        '''
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Post actions
    // ------------------------------------------------------------------
    post {
        always {
            script {
                // Clean up Docker images to save disk space
                sh '''
                    SERVICES="ui cart orders catalog checkout"
                    for svc in $SERVICES; do
                        IMAGE="${ECR_BASE_URL}/${ENVIRONMENT_NAME}-${svc}"
                        docker rmi ${IMAGE}:${IMAGE_TAG} 2>/dev/null || true
                        docker rmi ${IMAGE}:latest 2>/dev/null || true
                    done
                '''
            }

            // Archive reports
            archiveArtifacts artifacts: '**/trivy-report-*.json', allowEmptyArchive: true
            archiveArtifacts artifacts: '**/dependency-check-report/*.html', allowEmptyArchive: true
        }

        success {
            echo '========================================'
            echo 'PIPELINE SUCCESS — All security gates passed'
            echo "Image tag: ${env.IMAGE_TAG}"
            echo '========================================'
        }

        failure {
            echo '========================================'
            echo 'PIPELINE FAILED — Check security gate failures above'
            echo '========================================'
        }
    }
}

// ============================================================
// Helper: Build a single service based on its type
// ============================================================
def buildService(String service) {
    echo "Building service: ${service}"

    switch(service) {
        case 'ui':
        case 'cart':
        case 'orders':
            // Java Maven services
            sh './mvnw --no-transfer-progress -DskipTests package'
            break

        case 'catalog':
            // Go service
            sh 'go build -o dist/main main.go'
            break

        case 'checkout':
            // Node.js / TypeScript / NestJS service
            sh 'yarn install --frozen-lockfile'
            sh 'yarn build'
            break

        default:
            error "Unknown service type: ${service}"
    }
}
