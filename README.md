# typescript-aws-app

To run this project it’s necessary install node.js and serverless framework in your PC, you can download a node installer in this page:

https://nodejs.org/en/download/package-manager

After that you can install serverless framework with the command:

npm i serverless -g

Then in the root of the project use the command:

npm install

This command is for install all the dependencies of the project. 

Then in the .env file you will have to fill up all the keys, you will need an AWS account to get the ACCESS_KEY_ID and SECRET_ACCESS_KEY, also you will need an deployed MySQL instance, you can use the RDS service of AWS, after deploy your DB instance you have to put the database credentials (host, user, password, database) in the .env file.
In your MySQL manager (SQLyog, Workbench) you have to execute the queries in the db_structure.sql file, it’s necessary do this before start the project. 

Now you can start the project in your local PC with the command:

npm run dev

In the Typescrit-aws.postman_collection file you can consume the Api in your local, you will see the endpoints.

Also there is a swagger where you can use the API in any moment, this is already deployed in AWS:

https://app.swaggerhub.com/apis-docs/BRANDONVASQUEZBARRET/Test/1.0.0#/

To deploy in AWS, you must use the command:

npm run deploy

The consume is the same, only you have to replace http://localhost:3000/ with https://xxxxxxxxx.execute-api.us-east-1.amazonaws.com/

This AWS link is generated when the project is deployed.
