pipeline {
  agent any
  tools {
    maven 'MAVEN_HOME'
  }
  stages {
      stage('run test') {
        steps {
            bat 'mvn clean test'
        }
      }
      stage('SonarQube analysis') {
        steps {
            bat 'mvn clean package sonar:sonar -Dsonar.login=cffeccc79465dad21f396fd46ab0581765835948'
        }
      }
      stage('Deployment') {
        when {
            branch 'master'
        } 
        steps {
            echo 'This is a deployment'
        }
      }
  }
}

