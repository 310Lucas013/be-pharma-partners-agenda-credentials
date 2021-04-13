pipeline {
  agent any
  tools {
    maven 'MAVEN_HOME'
  }
  stages {
      stage('run test') {
        steps {
            bat 'mvn test'
        }
      }
      stage('SonarQube analysis') {
        steps {
            bat 'mvn clean package sonar:sonar -Dsonar.login=27ab6dc53812c5be56c778401a32443bc0614c11'
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

