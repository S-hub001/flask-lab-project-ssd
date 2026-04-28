// Full Name: Sukina Raveen
// Roll Number: 23i-2115
// Contribution: Added Jenkins build step – Sukina Raveen (23i-2115)

pipeline {
    agent any

    parameters {
        booleanParam(name: 'executeTests', defaultValue: true, description: 'Run test stage?')
    }

    stages {
        stage('Build') {
            steps {
                echo 'Building..'
            }
        }

        stage('Test') {
            when {
                expression { params.executeTests }
            }
            steps {
                echo 'Testing..'
            }
        }
    }
}