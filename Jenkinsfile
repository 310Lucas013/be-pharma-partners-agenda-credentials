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
//       stage('SonarQube analysis') {
//         steps {
//             bat 'mvn clean package sonar:sonar -Dsonar.login=2d21b6ecb01a7f36703ca2eac4f04729c17f2b03'
//         }
//       }
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

