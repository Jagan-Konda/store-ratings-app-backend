const express = require('express')
const sqlite3 = require('sqlite3')
const { open } = require('sqlite')
const path = require('path')

const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const cors = require('cors')


const dbPath = path.join(__dirname, './storeRatings.db')

const app = express()
app.use(express.json())

const allowedOrigins = ['http://localhost:3000'];

// CORS options
const corsOptions = {
    origin: allowedOrigins, // Allow only specific origins
};

// Apply CORS to all routes
app.use(cors(corsOptions));

let db = null

//Initializing DB and Server 

const initializeDBAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        })


        app.listen(3000, () => console.log("Server Running Successfully!"))
    } catch (e) {
        console.log(`DB Error: ${e.message}`)
        process.exit(1)
    }
}

initializeDBAndServer()



//Register A User API

app.post("/signup", async (request, response) => {
    const { name, email, password, address } = request.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const selectUserQuery = `SELECT * FROM user WHERE email = '${email}';`;
    const dbUser = await db.get(selectUserQuery);
    if (dbUser === undefined) {
        const createUserQuery = `
        INSERT INTO 
          user (name, email, password, address, role) 
        VALUES 
          (
            "${name}",
            "${email}",
            "${hashedPassword}", 
            "${address}",
            "Normal"
          )`;
        const dbResponse = await db.run(createUserQuery);
        const newUserId = dbResponse.lastID;
        response.status(201).json({ message: `Created new user with ID: ${newUserId}` });

    } else {
        response.status(400).json({ error: "User already exists" });
    }
});

//Login API 

app.post('/login', async (request, response) => {
    const { email, password } = request.body

    const queryToCheckUser = `
      SELECT *
      FROM user
      WHERE email = '${email}';
    `
    const dbUser = await db.get(queryToCheckUser)

    if (dbUser === undefined) {
        response.status(400).json({ error: 'Invalid user' });
    } else {
        const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
        if (isPasswordMatched) {
            const payload = { email: email }
            const jwtToken = jwt.sign(payload, 'SECRET')
            const responseObj = {
                jwt_token: jwtToken,
                role: dbUser.role
            }
            response.status(200).json(responseObj);
        } else {
            response.status(400).json({ error: 'Invalid password' });
        }
    }
})

//Token Verification

const authenticateToken = (request, response, next) => {
    let jwtToken
    const authorization = request.headers['authorization']

    if (authorization !== undefined) {
        jwtToken = authorization.split(' ')[1]
    }
    if (jwtToken === undefined) {
        response.status(401).json({ error: 'Invalid JWT Token' });
    } else {
        jwt.verify(jwtToken, 'SECRET', async (error, payload) => {
            if (error) {
                response.status(401).json({ error: 'Invalid JWT Token' });
            } else {
                request.email = payload.email
                next()
            }
        })
    }
}

//Restrict Admin Route

const authorizeAdmin = async (request, response, next) => {
    const { email } = request;
    const user = await db.get(`SELECT role FROM user WHERE email = ?`, [email]);
    if (user?.role !== 'Admin') {
        return response.status(403).json({ error: 'Access denied. Admins only.' });
    }
    next();
}

//Admin Stats API 

app.get('/admin/stats', authenticateToken, authorizeAdmin, async (request, response) => {
    try {
        const totalUsersQuery = `SELECT COUNT(id) AS total_users FROM user`;
        const totalStoresQuery = `SELECT COUNT(id) AS total_stores FROM store`;
        const totalRatingsQuery = `SELECT COUNT(id) AS total_ratings FROM ratings`;

        const totalUsers = await db.get(totalUsersQuery);
        const totalStores = await db.get(totalStoresQuery);
        const totalRatings = await db.get(totalRatingsQuery);

        response.send({
            total_users: totalUsers.total_users,
            total_stores: totalStores.total_stores,
            total_ratings: totalRatings.total_ratings
        });
    } catch (error) {
        console.error('Error fetching admin stats:', error);
        response.status(500).send({ error: 'Internal server error' });
    }
})

//API To Add a New User By Admin 

app.post('/admin/add-user', authenticateToken, authorizeAdmin, async (request, response) => {
    const { name, email, password, address, role } = request.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const selectUserQuery = `SELECT * FROM user WHERE email = '${email}'`;
    const dbUser = await db.get(selectUserQuery);
    if (dbUser === undefined) {
        const createUserQuery = `
        INSERT INTO 
          user (name, email, password, address, role) 
        VALUES 
          (
            "${name}",
            "${email}",
            "${hashedPassword}", 
            "${address}",
            "${role}"
          )`;
        const dbResponse = await db.run(createUserQuery);
        const newUserId = dbResponse.lastID;
        response.status(201).json({ message: `Created new user with ID: ${newUserId}` });

    } else {
        response.status(400).json({ error: "User already exists" });
    }
});

//API To Add a New Store By Admin 

app.post('/admin/add-store', authenticateToken, authorizeAdmin, async (request, response) => {
    const { name, address, email } = request.body;
    const queryToCheckIsUserPresentInUserTable = `
        SELECT *
        FROM user
        WHERE email = '${email}';
    `

    const isUserPresentInUserTable = await db.get(queryToCheckIsUserPresentInUserTable)
    if (!isUserPresentInUserTable) {
        return response.status(404).json({ error: "User does not exist" });
    }

    if (isUserPresentInUserTable.role !== "StoreOwner") {
        return response.status(400).json({ error: "User is not a store owner" });
    }

    if (isUserPresentInUserTable && isUserPresentInUserTable.role === "StoreOwner") {
        const queryToCheckIfUserAlreadyHadAStore = `
        SELECT *
        FROM store
        WHERE email = '${email}'`

        const dbResponse = db.all(queryToCheckIfUserAlreadyHadAStore)

        if (dbResponse.length !== 0) {
            return response.send({error: 'User Already Had A Store'})
        }
    }

    const queryToCreateNewStore = `
            INSERT INTO store (name,address,email)
            VALUES (
                "${name}",
                "${address}",
                "${email}"
            )
        `
    const dbResponse = await db.run(queryToCreateNewStore)
    response.status(201).json({ message: 'Store Added Successfully' })
});

//API To GET A List OF Stores 

app.get('/admin/stores', authenticateToken, authorizeAdmin, async (request, response) => {
    const { query } = request
    const { order_by = 'store.id' } = query
    const queryToGetListOfStores = `
        SELECT store.id, store.name, store.email, store.address, IFNULL(AVG(ratings.rating), 0) AS rating 
        FROM store LEFT JOIN ratings ON store.id = ratings.store_id
        GROUP BY store.id
        ORDER BY ${order_by};
    `
    const dbResponse = await db.all(queryToGetListOfStores)

    response.status(200).json(dbResponse)
})

//API To Get A List of Users

app.get('/admin/users', authenticateToken, authorizeAdmin, async (request, response) => {
    const { query } = request
    const { order_by = 'user.id' } = query

    const queryToGetListOfUsers = `
    
        SELECT 
            user.id,
            user.name,
            user.email,
            user.address,
            user.role,
            CASE 
                WHEN user.role = 'StoreOwner' THEN 
                    (SELECT IFNULL(AVG(ratings.rating), 0)
                    FROM store 
                    LEFT JOIN ratings ON store.id = ratings.store_id
                    WHERE store.email = user.email)
                ELSE NULL
            END AS average_rating
        FROM user
        ORDER BY ${order_by};
    `

    const dbResponse = await db.all(queryToGetListOfUsers)

    response.status(200).json(dbResponse)
})

//API To Update A Normal User's Password

app.put('/user/update-password', authenticateToken, async (request, response) => {
    const { email, newPassword } = request.body

    const hashedPassword = await bcrypt.hash(newPassword, 10)

    const queryToGetTheUser = `
        SELECT id
        FROM user
        WHERE email = '${email}';
    `
    const userId = await db.get(queryToGetTheUser)

    const queryToUpdatePassword = `
        UPDATE user
        SET password = '${hashedPassword}'
        WHERE id = ${userId.id};
    `

    const dbResponse = await db.run(queryToUpdatePassword)
    response.send('Password Updated Successfully')

})

//API to get List of stores By A Normal User

app.get('/user/stores', authenticateToken, async (request, response) => {
    const { query, email } = request
    const { order_by = 'store.id' } = query
    const userId = await db.get(`SELECT id FROM user WHERE email='${email}'`)
    const queryToGetListOfStores = `
        SELECT store.id, store.name, store.email, store.address, IFNULL(AVG(ratings.rating), 0) AS rating, (SELECT rating FROM ratings WHERE user_id = ${userId.id}) AS user_rating
        FROM store LEFT JOIN ratings ON store.id = ratings.store_id
        GROUP BY store.id
        ORDER BY ${order_by};
    `
    const dbResponse = await db.all(queryToGetListOfStores)

    response.status(200).json(dbResponse)
})

//API to Submit a rating by a normal user

app.post('/user/submit-rating/:id', authenticateToken, async (request, response) => {
    const { email, params } = request
    const { rating } = request.body
    const { id } = params

    const userId = await db.get(`SELECT id FROM user where email='${email}'`)
    const storeId = id

    const queryToCheckIsRatingAlreadyGiven = `
        SELECT *
        FROM ratings
        WHERE user_id = ${userId.id} AND store_id = ${storeId}
    `
    const isRatingAlreadyGiven = await db.all(queryToCheckIsRatingAlreadyGiven)

    if (isRatingAlreadyGiven.length !== 0) {
        return response.status(401).send('Rating Already Given')
    }

    const queryToSubmitARating = `
        INSERT INTO ratings (user_id, store_id, rating)
        VALUES (${userId.id}, ${storeId}, ${rating})
    `

    const dbResponse = await db.run(queryToSubmitARating)
    response.send('Rating Submitted Successfully!')
})

//API To Update Submitted Rating

app.put('/user/update-rating/:id', authenticateToken, async (request, response) => {
    const { email, params } = request
    const { rating } = request.body
    const { id } = params

    const userId = await db.get(`SELECT id FROM user WHERE email='${email}'`)
    const storeId = id

    const queryToSubmitARating = `
        UPDATE ratings 
        SET rating =  ${rating}
        WHERE store_id = ${storeId} AND user_id = ${userId.id};
    `

    const dbResponse = await db.run(queryToSubmitARating)
    response.send('Rating Updated Successfully!')
})

//API TO GET A LIST OF USERS WHO SUBMITTED RATING TO THE STORE

app.get('/store-owner/ratings', authenticateToken, async (request, response) => {
    const { email } = request

    const store = await db.get(`SELECT id FROM store WHERE email = '${email}'`)
    const storeId = store.id

    const queryToGetListOfRatingsOfAStore = `
        SELECT user.name, ratings.rating, (SELECT AVG(rating) FROM ratings WHERE store_id = ${storeId}) AS avg_rating
        FROM ratings LEFT JOIN user ON ratings.user_id = user.id 
        
    `

    const dbResponse = await db.all(queryToGetListOfRatingsOfAStore)
    response.send(dbResponse)
})