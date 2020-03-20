pipeline {
    agent {
        docker {
            image 'maven:3.6-jdk-13'
            args '-v /root/.m2:/root/.m2'
        }
    }

    options {
        timestamps()
    }

    environment {
        IMAGE = readMavenPom().getArtifactId()
        VERSION = readMavenPom().getVersion()
    }

    stages {
        stage('Build') {
            agent docker
            steps {
                sh 'mvn -Dmaven.test.skip -Dmaven.javadoc.skip install'
                sh 'pwd'
                sh 'ls -al'
            }
        }

        stage('Build and Publish Image') {
            agent docker
            when {
                branch 'master'  //only run these steps on the master branch
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'registry-deployment-credentials', passwordVariable: 'dockerPassword', usernameVariable: 'dockerUsername')]) {
                    sh 'pwd'
                    sh 'ls -al'
                    sh "docker build -t ${env.dockerRegistry}/${IMAGE}:${VERSION} ."
                    sh "docker login -u ${env.dockerUsername} -p ${env.dockerPassword} ${env.dockerRegistry}"
                    sh "docker push ${env.dockerRegistry}/${IMAGE}:${VERSION}"
                }
            }
        }
    }
}