import {APIGatewayProxyHandler} from 'aws-lambda';
import { OkPacket, createConnection } from "mysql2/promise";
import bcrypt from "bcryptjs";
import * as jwt from 'jsonwebtoken';
import * as dotenv from "dotenv";
import moment from 'moment';
import { Console } from 'console';

dotenv.config();

export const executeQuery = async (query: string, params: unknown[] = []) => {
    try {
        let connection = await createConnection({
            host: process.env.HOST,
            user: process.env.USER,
            password: process.env.PASSWORD,
            database: process.env.DATABASE
        });
        let results:any;
        await connection.query(query).then(([result]) => 
            results = result
        )
        connection.end()
        return results;
    } catch (error) {
        return { error };
    }
};

export const hashPassowrd = async (password:string, storedPassword:string) => {
    //let encrypted:any = await bcrypt.hash(password, 10);
    let encryptionValidation:any = await bcrypt.compare(password, storedPassword)
    return encryptionValidation;
};

export const tokenValidation = async (token:string) => {
    let sql:string = `${"SELECT t.*, u.user_state FROM tokens AS t INNER JOIN users AS u ON t.user_id = u.id WHERE t.token = " + "'" + token + "'"}`
    const result = await executeQuery(sql);
    let validation:boolean = false;
    let user_id:number;
    let role:string;
    let user_state:string;
    let dict = {};
    console.log(result)
    if (result.length > 0){
        role = result[0].role_user_logged;
        const expiry_date = result[0].expiry_date;
        user_id = result[0].user_id;
        user_state = result[0].user_state;
        const current_time = Math.floor(Date.now() / 1000);
        console.log(current_time);
        console.log(expiry_date);
        if(current_time > expiry_date){
            dict = {
                validation: false
            };
        }else{
            dict = {
                validation: true,
                user_id: user_id,
                role: role,
                user_state: user_state
            };
        }
    }else{
        dict = {
            validation: false
        };
    }
    return dict;
};

function isValidDate(dateString: string): boolean {
    const date = new Date(dateString);
    return !isNaN(date.getTime());
}

export const handler = async (event) => {
    console.log(event);
    const method = event.requestContext.http.method;
    const path = event.requestContext.http.path;
    console.log(method);
    console.log(path);
    let body:any
    try{
        body = JSON.parse(event.body);
    }catch{
        return{
            statusCode: 400,
            body: JSON.stringify({response: 'Syntax error in your json request'})
        };
    }
    
    if (method == "POST"){
        if (path == '/login'){
            const user = body.user;
            const password = body.password;
            let user_id:any;
            let role:any;
    
            let sql:string = `${"SELECT * FROM users WHERE username = " + "'" + user + "'"}`
            console.log(sql);
    
            const result = await executeQuery(sql);

            if (result.length > 0){
                const storedPassword = result[0].password;
                user_id = result[0].id;
                role = result[0].role;
                let user_state:any = result[0].user_state;
                if(user_state == "Blocked"){
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                    };
                }
                const hash = await hashPassowrd(password, storedPassword);
                if(hash === false){
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Wrong password'})
                    };
                }
            }
            else{
                return{
                    statusCode: 401,
                    body: JSON.stringify({response: 'User not found'})
                };
            }
            
            const current_time = Math.floor(Date.now() / 1000);
            const expiration_time = current_time + 86400; // one day duration
            const private_key = 'private_key';
            const claims = {
                'sub': 'public_key',
                'exp': expiration_time
            };

            const jwt_token = jwt.sign(claims, private_key, { algorithm: 'HS256' });
            console.log(current_time)
            console.log(expiration_time)

            let sql2:string = `${"INSERT INTO tokens(token, expiry_date, user_id, role_user_logged) VALUES(" + "'" + jwt_token + "', " + "'" + expiration_time + "', " + "'" + user_id + "', " + "'" + role + "')"}`
            const result2 = await executeQuery(sql2);

            return{
                statusCode: 200,
                body: JSON.stringify({response: jwt_token})
            };
        }else if(path == '/listUsers'){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    if(role != "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Insufficient permissions'})
                        };
                    }
                    let sql:string = `${"SELECT id, role, first_name, last_name, email, username, address, gender, birth_date, country, city, document_id, user_state, created_at, updated_at, deleted, deleted_at FROM users WHERE role = 'User'"}`
            
                    const result = await executeQuery(sql);
                    if(result.length == 0){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: "No users registered"})
                        };
                    }
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: result})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }  
            }
        }else if(path == "/registerUser"){
            const user = body.user;
            const email = body.email;
            const first_name = body.first_name;
            const last_name = body.last_name;
            const phone = body.phone;
            const password = body.password;
            const address = body.address;
            const gender = body.gender;
            const birth_date = body.birth_date;
            const country = body.country;
            const city = body.city;
            const document_id = body.document_id;
            
            if(!user || !email || !first_name || !last_name || !phone || !password || !address || !gender || !birth_date || !country || !city || !document_id){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Please fill out all fields'})
                };
            }
            if(user == "" || email == "" || first_name == "" || last_name == "" || phone == "" || password == "" || address == "" || gender == "" || birth_date == "" || country == "" || city == "" || document_id == ""){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Please fill out all fields'})
                };
            }

            const isDate = moment(birth_date, 'YYYY-MM-DD',true).isValid();
            if(!isDate){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Date format not valid, valid format: YYYY-MM-DD'})
                };
            }

            let sql:string = `${"SELECT * FROM users WHERE username = " + "'" + user + "'"}`
            let sql2:string = `${"SELECT * FROM users WHERE email = " + "'" + email + "'"}`
            const validation1 = await executeQuery(sql);
            const validation2 = await executeQuery(sql2);
            if(validation1.length > 0 || validation2.length > 0){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'User already registered or email already registered'})
                };
            }
            let encrypted:any = await bcrypt.hash(password, 10);

            let today = new Date();
            let dd = String(today.getDate()).padStart(2, '0');
            let mm = String(today.getMonth() + 1).padStart(2, '0');
            let yyyy = today.getFullYear();
            let dateToday = yyyy + '-' + mm + '-' + dd;

            let sqlUser:string = `${"INSERT INTO users(role, first_name, last_name, phone, email, username, PASSWORD, address, gender, birth_date, country, city, category, document_id, user_state, created_at, updated_at, deleted, deleted_at) VALUES('User', " + "'" + first_name + "', " + "'" + last_name + "', " + "'" + phone + "', " + "'" + email + "', " + "'" + user + "', "  +  "'" + encrypted + "', " + "'" + address + "', " + "'" + gender + "', " + "'" + birth_date + "', " + "'" + country + "', " + "'" + city + "', " + "'" + 1 + "', " + "'" + document_id + "', " + "'" + "Active" + "', " + "'" + dateToday + "', " + "NULL" + ", " + "'" + "NO" + "', " + "NULL" + ")"}`
            const insertUser = await executeQuery(sqlUser);

            let sqlAccount:string = `${"INSERT INTO accounts(amount, user_id) VALUES(" + "'" + "0" + "', " + "'" + insertUser.insertId + "')"}`
            console.log(sqlAccount);
            const insertAccount = await executeQuery(sqlAccount);
            return{
                statusCode: 200,
                body: JSON.stringify({response: 'User registered'})
            };
            
            
        }else if(path == "/deposit"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    let user_state:any = dict.user_state;
                    if(user_state == "Blocked"){
                        return{
                            statusCode: 401,
                            body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                        };
                    }
                    let user_id:any = dict.user_id;
                    const amount = body.amount;
                    
                    if(role == "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Admin roles cannot deposit'})
                        };
                    }

                    if(!amount || amount == "" || amount == 0){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Amount not sent'})
                        };
                    }

                    let depositSql:string = `${"UPDATE accounts SET amount = amount + " + amount + " WHERE user_id = " + user_id}`
                    const depositUpdate = await executeQuery(depositSql);

                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;
                    let transactionSql:string = `${"INSERT INTO transactions(user_id, amount, category, status, created_at) VALUES(" + user_id + ", " + amount + ", "+ "'" + "deposit" + "', " + "'" + "OK" + "', "+ "'" + dateToday + "')"}`
                    const transactionInsert = await executeQuery(transactionSql);
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'Transaction Successfull'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }  
            
            }
        }
        else if(path == "/withdraw"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    let user_state:any = dict.user_state;
                    if(user_state == "Blocked"){
                        return{
                            statusCode: 401,
                            body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                        };
                    }
                    let user_id:any = dict.user_id;
                    const amount = body.amount;
                    
                    if(role == "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Admin roles cannot withdraw'})
                        };
                    }

                    if(!amount || amount == "" || amount == 0){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Amount not sent'})
                        };
                    }

                    let accountSql:string = `${"SELECT * FROM accounts WHERE user_id = "  + user_id}`
                    const result = await executeQuery(accountSql);
                    const actualAmount = result[0].amount;
                    if(amount > actualAmount){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Insufficient balance'})
                        };
                    }
                    let depositSql:string = `${"UPDATE accounts SET amount = amount - " + amount + " WHERE user_id = " + user_id}`
                    const depositUpdate = await executeQuery(depositSql);

                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;
                    let transactionSql:string = `${"INSERT INTO transactions(user_id, amount, category, status, created_at) VALUES(" + user_id + ", " + amount + ", "+ "'" + "withdraw" + "', " + "'" + "OK" + "', "+ "'" + dateToday + "')"}`
                    const transactionInsert = await executeQuery(transactionSql);
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'Transaction Successfull'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }  
            
            }
        }else if(path == "/userBalance"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                console.log(validation)
                if(validation){
                    let role:any = dict.role;
                    let user_state:any = dict.user_state;
                    if(user_state == "Blocked"){
                        return{
                            statusCode: 401,
                            body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                        };
                    }
                    let user_id:any = dict.user_id;
                    
                    if(role == "Admin"){
                        user_id = body.user_id;
                        if(user_id == "" || !user_id){
                            return{
                                statusCode: 400,
                                body: JSON.stringify({response: 'Admin roles have to send an user_id to get user balance'})
                            };
                        }
                    }
                    let balanceSql:string = `${"SELECT amount, category FROM transactions WHERE user_id = "  + user_id}`
                    const results = await executeQuery(balanceSql);
                    let balance:number = 0;
                    if(results.length == 0){
                        if(role=="User"){
                            return{
                                statusCode: 200,
                                body: JSON.stringify({response: 'Current balance: 0'})
                            };
                        }else if(role=="Admin"){
                            let userSql:string = `${"SELECT role FROM users WHERE id = "  + user_id}`
                            const results = await executeQuery(userSql);
                            if(results.length == 0){
                                return{
                                    statusCode: 400,
                                    body: JSON.stringify({response: 'User_id does not exist'})
                                };
                            }else if(results[0].role == "User"){
                                return{
                                    statusCode: 200,
                                    body: JSON.stringify({response: 'Current balance: 0'})
                                };
                            }else if(results[0].role == "Admin"){
                                return{
                                    statusCode: 400,
                                    body: JSON.stringify({response: 'Admin roles do not have balance'})
                                };
                            }else{
                                return{
                                    statusCode: 400,
                                    body: JSON.stringify({response: 'Not a valid process'})
                                };
                            }
                            
                        }
                        
                    }
                    for (let result of results) {
                        let amountResult:number = result.amount;
                        let category:string = result.category
                        if(category == "deposit" || category == "winning"){
                            balance += amountResult
                        }else{
                            balance -= amountResult
                        }
                    }
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: `${"Current balance: "  + balance}`})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }  
            
            }
        }else if(path == "/transactions"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    let user_state:any = dict.user_state;
                    if(user_state == "Blocked"){
                        return{
                            statusCode: 401,
                            body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                        };
                    }
                    let user_id:any = dict.user_id;
                    let transactionSql:string;
                    if(role == "Admin"){
                        transactionSql = `${'SELECT amount, category, user_id, DATE_FORMAT(created_at, "%Y-%m-%d") as date_of_transaction FROM transactions WHERE status is not NULL'}`
                        const user_id = body.user_id;
                        const category = body.category;
                        if(user_id){
                            transactionSql += `${ ' AND user_id = ' + user_id}`
                        }
                        if(category){
                            transactionSql += `${ ' AND category = ' + "'" + category + "'"}`
                        }
                    }else{
                        transactionSql = `${'SELECT amount, category, DATE_FORMAT(created_at, "%Y-%m-%d") as date_of_transaction FROM transactions WHERE user_id = '  + user_id}`
                    }
                    const results = await executeQuery(transactionSql);
                    if(results.length == 0){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: 'No transactions for this user'})
                        };
                    }
                    
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: results})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }  
            
            }
        }else if(path == "/eventBet"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    let user_state:any = dict.user_state;
                    if(user_state == "Blocked"){
                        return{
                            statusCode: 401,
                            body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                        };
                    }
                    let user_id:any = dict.user_id;
                    const amount = body.amount;
                    const option = body.option;
                    const event_id = body.event_id;
                    
                    if(role == "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Admin roles cannot bet'})
                        };
                    }

                    if(!amount || !option || !event_id || amount == "" || option == "" || event_id == "" ){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Please fullfill of the fields'})
                        };
                    }

                    if(amount == 0 || option == 0){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Amount and option must be greater than 0'})
                        };
                    }

                    let betSql:string = `${"SELECT * FROM bets WHERE event_id = "  + "'" + event_id + "'" + "AND bet_option = " + option}`
                    const results = await executeQuery(betSql);
                    if(results.length == 0){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Event or bet option not found'})
                        };
                    }
                    if(results[0].status != "Active"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Event not active'})
                        };
                    }
                    const odd = results[0].odd;

                    let betValidationSql:string = `${"SELECT b.bet_option, b.event_id, b.odd, b.status, u.user_id FROM bets AS b INNER JOIN users_bets AS u ON b.event_id = u.bet_id WHERE u.bet_id = "  + "'" + event_id + "'" + "AND u.user_id = " + user_id + " AND u.state = 'open'"}`
                    const resultsValidation = await executeQuery(betValidationSql);
                    console.log(resultsValidation)
                    if(resultsValidation.length > 0){
                        const bet_option = resultsValidation[0].bet_option;
                        if(bet_option != option){
                            return{
                                statusCode: 400,
                                body: JSON.stringify({response: 'You cannot bet for another option when you already did a bet.'})
                            };
                        }
                        
                    }

                    let accountSql:string = `${"SELECT * FROM accounts WHERE user_id = "  + user_id}`
                    const result = await executeQuery(accountSql);
                    const actualAmount = result[0].amount;
                    
                    if(amount > actualAmount){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Insufficient balance'})
                        };
                    }

                    let depositSql:string = `${"UPDATE accounts SET amount = amount - " + amount + " WHERE user_id = " + user_id}`
                    const depositUpdate = await executeQuery(depositSql);

                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;

                    let userBetSql:string = `${"INSERT INTO users_bets(user_id, bet_id, odd, amount, bet_option, state, created_at) VALUES(" + user_id + ", " + "'" + event_id + "', " + odd + ", " + amount + ", " + option + ", " + "'" + "open" + "', " + "'" + dateToday + "')"}`
                    const userBetInsert = await executeQuery(userBetSql);
                    console.log(userBetInsert)
                    
                    let insertId:number = userBetInsert.insertId;
                    let transactionSql:string = `${"INSERT INTO transactions(user_id, amount, category, status, created_at, user_bet_id) VALUES(" + user_id + ", " + amount + ", "+ "'" + "bet" + "', " + "'" + "OK" + "', "+ "'" + dateToday + "', " + insertId + ")"}`
                    const transactionInsert = await executeQuery(transactionSql);

                    
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'Transaction Successfull'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }  
            
            }
        }else if(path == "/listBets"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    let user_state:any = dict.user_state;
                    if(user_state == "Blocked"){
                        return{
                            statusCode: 401,
                            body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                        };
                    }
                    let user_id:any = dict.user_id;
                    const event_id = body.event_id;
                    const sport = body.sport;
                    let betsSql:string = `${'SELECT * FROM bets WHERE status is not null'}`
                    
                    if(event_id){
                        betsSql += `${' AND event_id = ' + "'" + event_id + "'"}`
                    }
                    if(sport){
                        betsSql += `${' AND sport = ' + "'" + sport + "'"}`
                    }
                    
                    const results = await executeQuery(betsSql);
                    
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: results})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }  
            
            }
        }
        else{
            return{
                statusCode: 404,
                body: JSON.stringify({response: 'Module not found'})
            }; 
        }
    }else if(method == "PATCH"){
        if(path == "/updateUser"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    let user_state:any = dict.user_state;
                    console.log(user_state)
                    if(user_state == "Blocked"){
                        return{
                            statusCode: 401,
                            body: JSON.stringify({response: 'User blocked, please contact an admin user'})
                        };
                    }
                    let user_id:any;
                    const first_name = body.first_name;
                    const last_name = body.last_name;
                    const phone = body.phone;
                    const address = body.address;
                    const gender = body.gender;
                    const birth_date = body.birth_date;
                    const country = body.country;
                    const city = body.city;
                    const document_id = body.document_id;
                    
                    if(role == "Admin"){
                        user_id = body.user_id;
                        if(user_id == "" || !user_id){
                            return{
                                statusCode: 400,
                                body: JSON.stringify({response: 'Admin roles have to send an user_id to update'})
                            };
                        }
                        let sql:string = `${"SELECT * FROM users WHERE id = " + user_id}`
                        const result = await executeQuery(sql);
                        if(result.length == 0){
                            return{
                                statusCode: 404,
                                body: JSON.stringify({response: 'User not found'})
                            };
                        }
                        if(result[0].role == "Admin"){
                            return{
                                statusCode: 400,
                                body: JSON.stringify({response: 'You cannot update data of admin roles'})
                            };
                        }
                    }else{
                        user_id = dict.user_id;
                    }

                    if(first_name == "" || last_name == "" || phone == "" || address == "" || gender == "" || birth_date == "" || country == "" || city == "" || document_id == ""){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Please do not leave empty fields'})
                        };
                    }
                    const isDate = moment(birth_date, 'YYYY-MM-DD',true).isValid();
                    if(!isDate){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Format date not valid, valid format: YYYY-MM-DD'})
                        };
                    }
                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;
                    let updateSql:string = `${"UPDATE users SET updated_at = " + "'" + dateToday + "'"}`
                    
                    if(first_name){
                        updateSql += `${", first_name = "+ "'" + first_name + "'"}`
                    }
                    if(last_name){
                        updateSql += `${", last_name = "+ "'" + last_name + "'"}`
                    }
                    if(phone){
                        updateSql += `${", phone = "+ "'" + phone + "'"}`
                    }
                    if(address){
                        updateSql += `${", address = "+ "'" + address + "'"}`
                    }
                    if(gender){
                        updateSql += `${", gender = "+ "'" + gender + "'"}`
                    }
                    if(country){
                        updateSql += `${", country = "+ "'" + country + "'"}`
                    }
                    if(birth_date){
                        updateSql += `${", birth_date = "+ "'" + birth_date + "'"}`
                    }
                    if(city){
                        updateSql += `${", city = "+ "'" + city + "'"}`
                    }
                    if(document_id){
                        updateSql += `${", document_id = "+ "'" + document_id + "'"}`
                    }
                    updateSql += `${" WHERE id = " + user_id }`
                    const updateUser = await executeQuery(updateSql);
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'User updated'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }   
                    
            }
        }else if(path == "/updateBetStatus"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    let user_id:any;
                    const event_id = body.event_id;
                    const status = body.status;
                    
                    if(role != "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Insufficient permissions'})
                        };
                    }

                    if(event_id == "" || status == "" || !event_id || !status){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Please do not leave empty fields'})
                        };
                    }
                    let valid_status = ["Active", "Cancelled"];
                    const validation = valid_status.includes(status);
                    if(!validation){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Not a valid status, valid status: Active or Cancelled'})
                        };
                    }

                    let betsSql:string = `${'SELECT status FROM bets WHERE event_id = ' + "'" + event_id + "'"}`
                    const results = await executeQuery(betsSql);
                    if(results.length == 0){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: 'Event id not found'})
                        };
                    }
                    if(status == "Cancelled"){
                        for(let result of results){
                            if(result.status == "Settled"){
                                return{
                                    statusCode: 404,
                                    body: JSON.stringify({response: 'Already settled bets can not be cancelled'})
                                };
                            }else if(result.status == "Active"){
                                let userbetsSql:string = `${'SELECT * FROM users_bets WHERE bet_id = ' + "'" + event_id + "'"}`
                                const results = await executeQuery(userbetsSql);
                                if(results.length > 0){
                                    return{
                                        statusCode: 400,
                                        body: JSON.stringify({response: 'Active bets where users made a bet cannot be cancelled'})
                                    };
                                }
                            }
                        }
                    }
                    
                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;
                    let updateSql:string = `${"UPDATE bets SET updated_at = " + "'" + dateToday + "'" + ", status = "+ "'" + status + "'" + " WHERE event_id = " + "'" + event_id + "'"}`
                    
                    const updateBet = await executeQuery(updateSql);
                    
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'Bet status updated'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }   
                    
            }
        }else if(path == "/blockUser"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    const user_id = body.user_id;
                    
                    if(role != "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Insufficient permissions'})
                        };
                    }

                    if(user_id == "" || !user_id){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Please send an user id'})
                        };
                    }

                    let betsSql:string = `${'SELECT role FROM users WHERE id = ' + user_id }`
                    const results = await executeQuery(betsSql);
                    if(results.length == 0){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: 'User id not found'})
                        };
                    }
                    if(results[0].role == "Admin"){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: 'Cannot block Admin users'})
                        };
                    }
                    
                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;
                    let updateSql:string = `${"UPDATE users SET updated_at = " + "'" + dateToday + "'" + ", user_state = "+ "'" + "Blocked" + "'" + " WHERE id = " + user_id }`
                    
                    const updateBet = await executeQuery(updateSql);
                    
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'User blocked'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }   
                    
            }
        }else if(path == "/unblockUser"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    const user_id = body.user_id;
                    
                    if(role != "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Insufficient permissions'})
                        };
                    }

                    if(user_id == "" || !user_id){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Please send an user id'})
                        };
                    }

                    let betsSql:string = `${'SELECT role FROM users WHERE id = ' + user_id }`
                    const results = await executeQuery(betsSql);
                    if(results.length == 0){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: 'User id not found'})
                        };
                    }
                    if(results[0].role == "Admin"){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: 'Cannot block Admin users'})
                        };
                    }
                    
                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;
                    let updateSql:string = `${"UPDATE users SET updated_at = " + "'" + dateToday + "'" + ", user_state = "+ "'" + "Active" + "'" + " WHERE id = " + user_id }`
                    
                    const updateBet = await executeQuery(updateSql);
                    
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'User unblocked'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }   
                    
            }
        }else if(path == "/settleBet"){
            const token = body.token;
            if(!token){
                return{
                    statusCode: 400,
                    body: JSON.stringify({response: 'Token not sent'})
                }; 
            }else{
                let dict:any = await tokenValidation(token);
                let validation:any = dict.validation;
                if(validation){
                    let role:any = dict.role;
                    const event_id = body.event_id;
                    const winner_option = Number(body.winner_option)
                    
                    if(role != "Admin"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Insufficient permissions'})
                        };
                    }

                    if(event_id == "" || !event_id || winner_option == 0 || !winner_option){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Please do not leave empty fields or winner option in 0'})
                        };
                    }

                    let betsSql:string = `${'SELECT * FROM bets WHERE event_id =' + "'" + event_id + "'"}`
                    let results = await executeQuery(betsSql);
                    if(results.length == 0){
                        return{
                            statusCode: 404,
                            body: JSON.stringify({response: 'Event id not found'})
                        };
                    }
                    const validationStatus = results[0].status
                    if(validationStatus == "Settled" || validationStatus == "Cancelled"){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Cannot settle already settled or cancelled bets'})
                        };
                    }
                    let options:Array<any> = [];
                    for(let result of results){
                        options.push(result.bet_option);
                    }
                    const validation = options.includes(winner_option);
                    if(!validation){
                        return{
                            statusCode: 400,
                            body: JSON.stringify({response: 'Bet option not found in event, please send the correct NUMBER option'})
                        };
                    }
                    
                    let today = new Date();
                    let dd = String(today.getDate()).padStart(2, '0');
                    let mm = String(today.getMonth() + 1).padStart(2, '0');
                    let yyyy = today.getFullYear();
                    let dateToday = yyyy + '-' + mm + '-' + dd;
                    let updateSql:string = `${"UPDATE bets SET updated_at = " + "'" + dateToday + "'" + ", status = "+ "'" + "Settled" + "', " + "result = CASE WHEN bet_option = " + winner_option + " THEN 'Win' ELSE 'Lost' END " + " WHERE event_id = " + "'" + event_id + "'" }`
                    
                    const updateBet = await executeQuery(updateSql);

                    betsSql = `${'SELECT u.id, u.user_id, u.odd, u.amount, b.bet_option, b.result, b.event_id FROM bets AS b INNER JOIN users_bets AS u ON b.event_id = u.bet_id AND b.bet_option = u.bet_option WHERE b.result = "Win" AND u.state = "open" AND b.event_id =' + "'" + event_id + "'"}`
                    results = await executeQuery(betsSql);

                    for(let result of results){
                        let user_bet_id = result.id
                        let amount = result.amount
                        let odd = result.odd
                        let user_id = result.user_id
                        let sum = amount * odd
                        let depositSql:string = `${"UPDATE accounts SET amount = amount + " + sum + " WHERE user_id = " + user_id}`
                        //console.log(depositSql)
                        const depositUpdate = await executeQuery(depositSql);
                        let transactionSql:string = `${"INSERT INTO transactions(user_id, amount, category, status, created_at, user_bet_id) VALUES(" + user_id + ", " + sum + ", "+ "'" + "winning" + "', " + "'" + "OK" + "', "+ "'" + dateToday + "', " + user_bet_id + ")"}`
                        //console.log(transactionSql)
                        const transactionInsert = await executeQuery(transactionSql);
                    }
                    let updateUserBetsSql:string = `${"UPDATE users_bets SET state = CASE WHEN bet_option = " + winner_option + " THEN 'won' ELSE 'lost' END WHERE bet_id = " + "'" + event_id + "'"}`
                    const updateUserBets = await executeQuery(updateUserBetsSql);
                    return{
                        statusCode: 200,
                        body: JSON.stringify({response: 'Process successful'})
                    };
                }else{
                    return{
                        statusCode: 401,
                        body: JSON.stringify({response: 'Please Login'})
                    };
                }   
                    
            }
        }else{
            return{
                statusCode: 404,
                body: JSON.stringify({response: 'Module not found'})
            }; 
        }
    }else{
        return{
            statusCode: 404,
            body: JSON.stringify({response: 'Method not established'})
        }; 
    }
    

};