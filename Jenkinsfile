// ============================================================
// Jenkinsfile — DevSecOps CI Pipeline
// Capstone Project: DevSecOps + GitOps for Microservices on AWS
//
// Shared Library: jenkins-shared-library/
//   Provides reusable functions for build, scan, push, and GitOps.
//   Ref: https://www.jenkins.io/doc/book/pipeline/shared-libraries/
//
// Prerequisites (Jenkins Global Config):
//   1. Add shared library: Manage Jenkins > Configure System > Global Pipeline Libraries
//      Name: devsecops-shared-library
//      Default version: main
//      Retrieval method: Modern SCM > Git > github.com/min-hit-1701/devsecops-gitops-microservices
//      Library path: 05-ci/jenkins-shared-library
//   2. Add credentials:
//      aws-credentials     — Type: AWS Credentials
//      OWASP_NVD_API_KEY   — Type: Secret text
//      gitops-deploy-key   — Type: SSH private key
//   3. Plugins required: CloudBees AWS Credentials, Amazon ECR, Docker Pipeline, SonarQube Scanner
// ============================================================

@Library('devsecops-shared-library') _

pipeline {
    agent any

    environment {
        AWS_REGION             = 'ap-southeast-1'
        AWS_CREDENTIALS_ID     = 'aws-credentials'
        ENVIRONMENT_NAME       = 'uit-devsecops-dev'

        APP_REPO_URL           = 'https://github.com/min-hit-1701/retail-store-app.git'
        GITOPS_REPO_URL        = 'https://github.com/min-hit-1701/retail-store-gitops.git'
        GITOPS_REPO_PATH       = '/tmp/gitops-repo'

        SERVICES               = 'ui,cart,orders,catalog,checkout'

        SONAR_HOST_URL         = 'http://sonarqube:9000'
        SONAR_PROJECT_KEY      = 'uit-devsecops-retail-store'
        OWASP_NVD_API_KEY      = credentials('OWASP_NVD_API_KEY')

        IMAGE_TAG              = "${env.GIT_COMMIT ? env.GIT_COMMIT.take(7) : 'latest'}"
        TRIVY_SEVERITY         = 'CRITICAL,HIGH'
    }

    parameters {
        string(name: 'GIT_BRANCH', defaultValue: 'main', description: 'Branch to build')
        string(name: 'IMAGE_TAG_OVERRIDE', defaultValue: '', description: 'Override image tag')
    }

    stages {

        stage('Checkout') {
            steps {
                script {
                    checkout([
                        $class: 'GitSCM',
                        branches: [[name: "${params.GIT_BRANCH}"]],
                        userRemoteConfigs: [[url: "${env.APP_REPO_URL}"]]
                    ])

                    if (params.IMAGE_TAG_OVERRIDE?.trim()) {
                        env.IMAGE_TAG = params.IMAGE_TAG_OVERRIDE.trim()
                    }

                    echo "Branch: ${params.GIT_BRANCH} | Image tag: ${env.IMAGE_TAG}"
                }
            }
        }

        stage('AWS Setup') {
            steps { awsSetup() }
        }

        stage('Build') {
            steps {
                script {
                    def builds = [:]
                    env.SERVICES.split(',').each { svc ->
                        builds[svc] = {
                            dir("src/${svc}") { buildService(svc.trim()) }
                        }
                    }
                    parallel builds
                }
            }
        }

        stage('SonarQube SAST') {
            steps { sonarQubeAnalysis() }
        }

        stage('OWASP Dependency Check') {
            steps { owaspDependencyCheck() }
        }

        stage('Docker Build, Scan & Push') {
            steps { dockerBuildAndPush() }
        }

        stage('Update GitOps Repo') {
            steps { updateGitOpsRepo() }
        }
    }

    post {
        always {
            script {
                sh '''
                    SERVICES="ui cart orders catalog checkout"
                    for svc in $SERVICES; do
                        IMAGE="${ECR_BASE_URL}/${ENVIRONMENT_NAME}-${svc}"
                        docker rmi ${IMAGE}:${IMAGE_TAG} 2>/dev/null || true
                        docker rmi ${IMAGE}:latest 2>/dev/null || true
                    done
                '''
            }

            archiveArtifacts artifacts: '**/trivy-report-*.json', allowEmptyArchive: true
            archiveArtifacts artifacts: '**/dependency-check-report/*.html', allowEmptyArchive: true
        }

        success {
            echo "========================================"
            echo "PIPELINE SUCCESS — All security gates passed"
            echo "Image tag: ${env.IMAGE_TAG}"
            echo "========================================"
        }

        failure {
            echo "========================================"
            echo "PIPELINE FAILED — Check security gate failures above"
            echo "========================================"
        }
    }
}
