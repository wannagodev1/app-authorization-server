pipeline {

  /*
   * Run everything on an existing agent configured with a label 'docker'.
   * This agent will need docker, git and a jdk installed at a minimum.
   */
  agent any

  // using the Timestamper plugin we can add timestamps to the console log
  options {
    timestamps()
  }

  parameters {
    string(name: 'dockerRegistry', description: 'Push Registry server name')
  }

  environment {
    //Use Pipeline Utility Steps plugin to read information from pom.xml into env variables
    IMAGE = readMavenPom().getArtifactId()
    VERSION = readMavenPom().getVersion()
  }

  stages {
    stage('Build') {
      agent {
        docker {
          image 'maven:3.6-jdk-13'
          args '-v /root/.m2:/root/.m2'
        }
      }
      steps {
          sh 'mvn -Dmaven.test.skip -Dmaven.javadoc.skip package'
      }
      post {
        success {
          // we only worry about archiving the jar file if the build steps are successful
          archiveArtifacts(artifacts: '**/target/*.jar', allowEmptyArchive: true)
        }
      }
    }

    stage('Build and Publish Image') {
      when {
        branch 'master'  //only run these steps on the master branch
      }
      steps {
      withCredentials([usernamePassword(credentialsId: 'registry-deployment-credentials', passwordVariable: 'dockerPassword', usernameVariable: 'dockerUsername')]) {
        sh "docker build -t ${params.dockerRegistry}/${IMAGE}:${VERSION} ."
        sh "docker login -u ${env.dockerUsername} -p ${env.dockerPassword} ${params.dockerRegistry}"
        sh "docker push ${params.dockerRegistry}/${IMAGE}:${VERSION}"
        }
      }
    }
  }

  post {
    failure {
      // notify users when the Pipeline fails
      mail to: 'Alexandre.Clavaud@ilemgroup.com',
          subject: "Failed Pipeline: ${currentBuild.fullDisplayName}",
          body: "Something is wrong with ${env.BUILD_URL}"
    }
  }
}