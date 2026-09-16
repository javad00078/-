import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';

const db = new PrismaClient();

const app = express();

const PORT = Number(process.env.PORT || 4000);
const SECRET = process.env.JWT_SECRET || 'dev-secret';

app.use(helmet());

app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
  })
);

app.use(express.json());
app.use(cookieParser());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 400,
  })
);


const createToken = (user: any) => {
  return jwt.sign(
    {
      id: user.id,
    },
    SECRET,
    {
      expiresIn: '12h',
    }
  );
};


const auth = async (
  req: any,
  res: any,
  next: any
) => {
  try {
    const token =
      req.cookies.lspd_token ||
      req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required',
      });
    }


    const payload: any = jwt.verify(
      token,
      SECRET
    );


    const user = await db.user.findUnique({
      where: {
        id: payload.id,
      },
      include: {
        rank: true,
        division: true,
        userPermissions: {
          include: {
            permission: true,
          },
        },
      },
    });


    if (!user || !user.active) {
      return res.status(401).json({
        error: 'Inactive account',
      });
    }


    req.user = user;

    next();

  } catch {

    return res.status(401).json({
      error: 'Invalid session',
    });

  }
};



const permission = (key: string) => {

  return (
    req: any,
    res: any,
    next: any
  ) => {


    const permissions =
      req.user.userPermissions.map(
        (p: any) =>
          p.permission.key
      );


    if (
      req.user.isOwner ||
      permissions.includes(key)
    ) {
      return next();
    }


    return res.status(403).json({
      error: 'Permission denied',
    });

  };

};



const audit = async (
  req: any,
  action: string,
  targetType: string,
  targetId: string | null,
  details: any
) => {

  return db.auditLog.create({

    data: {

      actorId: req.user?.id || null,

      action,

      targetType,

      targetId,

      details: JSON.stringify(details),

      ipAddress: req.ip,

    },

  });

};



app.get(
  '/api/health',
  (_req, res) => {

    res.json({
      ok: true,
      service: 'Vanguard LSPD API',
    });

  }
);



app.post(
  '/api/auth/login',
  async (req, res) => {


    const result = z
      .object({
        username: z.string(),
        password: z.string(),
      })
      .safeParse(req.body);



    if (!result.success) {

      return res.status(400).json({
        error: 'Invalid input',
      });

    }



    const user =
      await db.user.findUnique({

        where: {
          username:
            result.data.username.toLowerCase(),
        },

        include: {
          rank: true,
          division: true,
        },

      });



    if (
      !user ||
      !user.active ||
      !(await argon2.verify(
        user.passwordHash,
        result.data.password
      ))
    ) {

      return res.status(401).json({
        error:
          'Username or password incorrect',
      });

    }



    await db.user.update({

      where:{
        id:user.id,
      },

      data:{
        online:true,
        lastLogin:new Date(),
      },

    });



    res.cookie(
      'lspd_token',
      createToken(user),
      {
        httpOnly:true,
        sameSite:'lax',
        secure:
          process.env.COOKIE_SECURE === 'true',
        maxAge:
          12 * 60 * 60 * 1000,
      }
    );



    await audit(
      {
        user,
        ip:req.ip,
      },
      'LOGIN',
      'User',
      user.id,
      {}
    );



    return res.json({
      user:{
        ...user,
        passwordHash:undefined,
      },
    });


  }
);app.post(
  '/api/auth/logout',
  auth,
  async (req, res) => {

    await db.user.update({
      where:{
        id:req.user.id,
      },
      data:{
        online:false,
      },
    });


    res.clearCookie(
      'lspd_token'
    );


    return res.json({
      ok:true,
    });

  }
);



app.get(
  '/api/auth/me',
  auth,
  async (req,res)=>{

    return res.json({
      user:req.user,
    });

  }
);



app.post(
  '/api/auth/change-password',
  auth,
  async(req,res)=>{


    const result = z.object({

      currentPassword:z.string(),

      newPassword:
        z.string().min(8),

    }).safeParse(req.body);



    if(!result.success){

      return res.status(400).json({
        error:'Invalid password',
      });

    }



    const valid =
      await argon2.verify(
        req.user.passwordHash,
        result.data.currentPassword
      );



    if(!valid){

      return res.status(400).json({
        error:'Current password incorrect',
      });

    }



    await db.user.update({

      where:{
        id:req.user.id,
      },

      data:{
        passwordHash:
          await argon2.hash(
            result.data.newPassword
          ),
      },

    });



    return res.json({
      ok:true,
    });


  }
);



app.post(
  '/api/auth/forgot-password',
  async(req,res)=>{


    const username =
      String(
        req.body.username
      ).toLowerCase();



    const user =
      await db.user.findUnique({

        where:{
          username,
        },

      });



    if(user){

      const token =
        crypto
        .randomBytes(32)
        .toString('hex');



      await db.passwordReset.create({

        data:{

          userId:user.id,

          token,

          expiresAt:
            new Date(
              Date.now()+30*60*1000
            ),

        },

      });

    }



    return res.json({
      ok:true,
    });

  }
);





/*
========================
 DASHBOARD
========================
*/


app.get(
  '/api/dashboard',
  auth,
  async(_req,res)=>{


    const [

      players,

      online,

      coins,

      activities,

      pending,

      announcements,

      topCoin,

      topTime,

    ] =
    await Promise.all([


      db.user.count(),



      db.user.count({

        where:{
          online:true,
          active:true,
        },

      }),



      db.user.aggregate({

        _sum:{
          coin:true,
        },

      }),



      db.activity.count(),



      db.activity.count({

        where:{
          status:'PENDING',
        },

      }),



      db.announcement.findMany({

        take:5,

        orderBy:{
          createdAt:'desc',
        },

        include:{

          author:{
            select:{
              name:true,
            },
          },

        },

      }),



      db.user.findMany({

        take:5,

        orderBy:{
          coin:'desc',
        },

        include:{
          rank:true,
          division:true,
        },

      }),



      db.user.findMany({

        take:5,

        orderBy:{
          playtimeMinutes:'desc',
        },

        include:{
          rank:true,
        },

      }),


    ]);



    return res.json({

      stats:{

        players,

        online,

        coins:
          coins._sum.coin || 0,

        activities,

        pending,

      },


      announcements,

      topCoin,

      topTime,


    });


  }
);





/*
========================
 USERS
========================
*/


app.get(
 '/api/users',
 auth,
 permission('players.view'),
 async(_req,res)=>{


  const users =
    await db.user.findMany({

      orderBy:[

        {
          online:'desc',
        },

        {
          name:'asc',
        },

      ],


      include:{

        rank:true,

        division:true,

      },

    });



  return res.json({
    users,
  });


 }
);




app.post(
 '/api/users',
 auth,
 permission('players.create'),
 async(req,res)=>{


 const result =
 z.object({

   username:
     z.string().min(3),

   password:
     z.string().min(8),

   name:
     z.string().min(2),


   rankId:
     z.string(),


   divisionId:
     z.string()
     .nullable()
     .optional(),


   discordId:
     z.string()
     .optional(),


   coin:
     z.number()
     .int()
     .min(0)
     .default(0),


 }).safeParse(req.body);




 if(!result.success){

  return res.status(400).json({

    error:'Invalid officer data',

  });

 }




 const user =
 await db.user.create({

 data:{


 username:
 result.data.username.toLowerCase(),


 passwordHash:
 await argon2.hash(
   result.data.password
 ),


 name:
 result.data.name,


 rankId:
 result.data.rankId,


 divisionId:
 result.data.divisionId || null,


 discordId:
 result.data.discordId,


 coin:
 result.data.coin,


 },


 });





 await audit(

 req,

 'PLAYER_CREATED',

 'User',

 user.id,

 {
  name:user.name,
 }

 );




 return res.status(201).json({

 user,

 });


 }
);/*
========================
 COIN SYSTEM
========================
*/


app.post(
 '/api/users/:id/coins',
 auth,
 permission('coin.add'),
 async(req,res)=>{


 const result =
 z.object({

  amount:
   z.number()
   .int()
   .positive(),


  reason:
   z.string()
   .min(2),


 }).safeParse(req.body);



 if(!result.success){

  return res.status(400).json({
   error:'Invalid coin data',
  });

 }



 const user =
 await db.user.update({

  where:{
   id:req.params.id,
  },


  data:{

   coin:{
    increment:
     result.data.amount,
   },

  },


 });



 await db.coinTransaction.create({

  data:{

   userId:
    user.id,


   actorId:
    req.user.id,


   amount:
    result.data.amount,


   type:
    'ADMIN_ADD',


   reason:
    result.data.reason,


  },

 });



 await audit(

 req,

 'COIN_ADDED',

 'User',

 user.id,

 result.data

 );



 return res.json({
  user,
 });


 }
);







/*
========================
 RANK MANAGEMENT
========================
*/


app.post(
 '/api/users/:id/rank',
 auth,
 permission('rank.promote'),
 async(req,res)=>{


 const user =
 await db.user.findUnique({

  where:{
   id:req.params.id,
  },


  include:{
   rank:true,
  },

 });



 const rank =
 await db.rank.findUnique({

  where:{
   id:req.body.rankId,
  },

 });



 if(!user || !rank){

  return res.status(404).json({

   error:'Rank or user not found',

  });

 }



 await db.$transaction([


  db.user.update({

   where:{
    id:user.id,
   },


   data:{
    rankId:rank.id,
   },


  }),



  db.rankHistory.create({

   data:{


    userId:
     user.id,


    fromRank:
     user.rank.name,


    toRank:
     rank.name,


    reason:
     req.body.reason ||
     'Command action',


    actorId:
     req.user.id,


   },


  }),



 ]);




 await audit(

 req,

 'RANK_CHANGED',

 'User',

 user.id,

 {

  from:user.rank.name,

  to:rank.name,

 }

 );




 return res.json({

  ok:true,

 });


 }
);







/*
========================
 ACTIVITY SYSTEM
========================
*/


app.get(
 '/api/activities/mine',
 auth,
 async(req,res)=>{


 const activities =
 await db.activity.findMany({

  where:{
   userId:req.user.id,
  },


  orderBy:{
   createdAt:'desc',
  },


  take:100,


 });



 return res.json({

  activities,

 });


 }
);






app.post(
 '/api/activities',
 auth,
 async(req,res)=>{


 const result =
 z.object({

  type:
   z.string(),


  location:
   z.string(),


  occurredAt:
   z.string(),


  description:
   z.string()
   .min(10),


  dispatchId:
   z.string()
   .nullable()
   .optional(),


 }).safeParse(req.body);





 if(!result.success){

  return res.status(400).json({

   error:'Invalid activity',

  });

 }





 const activity =
 await db.activity.create({

  data:{


   type:
    result.data.type,


   location:
    result.data.location,


   occurredAt:
    new Date(
     result.data.occurredAt
    ),


   description:
    result.data.description,


   dispatchId:
    result.data.dispatchId || null,


   userId:
    req.user.id,


  },

 });





 await audit(

 req,

 'ACTIVITY_SUBMITTED',

 'Activity',

 activity.id,

 {

  type:
   activity.type,

 }

 );




 return res.status(201).json({

  activity,

 });


 }
);







/*
========================
 DISPATCH VERIFY
========================
*/


app.get(
 '/api/activities/pending',
 auth,
 permission('activity.verify'),
 async(_req,res)=>{


 const activities =
 await db.activity.findMany({

  where:{
   status:'PENDING',
  },


  orderBy:{
   createdAt:'asc',
  },


  include:{


   user:true,


  },

 });



 return res.json({

  activities,

 });


 }
);






app.post(
 '/api/activities/:id/verify',
 auth,
 permission('activity.verify'),
 async(req,res)=>{


 const activity =
 await db.activity.findUnique({

  where:{
   id:req.params.id,
  },

 });



 if(!activity){

  return res.status(404).json({

   error:'Activity not found',

  });

 }




 const approved =
 Boolean(
  req.body.approved
 );




 await db.$transaction(async(tx)=>{


  await tx.activity.update({

   where:{
    id:activity.id,
   },


   data:{


    status:
     approved
     ? 'APPROVED'
     : 'REJECTED',


    verifiedById:
     req.user.id,


    verifiedAt:
     new Date(),


    verificationReason:
     req.body.reason,


   },

  });




  if(approved){


   await tx.user.update({

    where:{
     id:activity.userId,
    },


    data:{

     coin:{
      increment:
       activity.coinReward,
     },


    },


   });



   await tx.coinTransaction.create({

    data:{


     userId:
      activity.userId,


     actorId:
      req.user.id,


     amount:
      activity.coinReward,


     type:
      'ACTIVITY_REWARD',


     reason:
      activity.type,


    },

   });


  }


 });




 await audit(

 req,

 approved
 ? 'ACTIVITY_APPROVED'
 : 'ACTIVITY_REJECTED',

 'Activity',

 activity.id,

 {}


 );




 return res.json({

  ok:true,

  coinAwarded:
   approved
   ? activity.coinReward
   : 0,


 });


 }
);/*
========================
 DIVISION SYSTEM
========================
*/


app.get(
 '/api/divisions',
 auth,
 async(_req,res)=>{


 const divisions =
 await db.division.findMany({

  orderBy:{
   name:'asc',
  },

 });


 return res.json({

  divisions,

 });


 }
);





app.post(
 '/api/divisions/request',
 auth,
 async(req,res)=>{


 const division =
 await db.division.findUnique({

  where:{
   id:req.body.divisionId,
  },

 });



 if(!division){

  return res.status(404).json({

   error:'Division not found',

  });

 }




 if(
  req.user.rank.level <
  division.minimumRankLevel
 ){

  return res.status(403).json({

   error:'Rank too low',

  });

 }





 const request =
 await db.divisionRequest.create({

  data:{


   userId:
    req.user.id,


   divisionId:
    division.id,


   message:
    req.body.message || '',


  },

 });




 return res.status(201).json({

  request,

 });


 }
);






app.get(
 '/api/divisions/requests',
 auth,
 permission('division.assign'),
 async(_req,res)=>{


 const requests =
 await db.divisionRequest.findMany({

  where:{
   status:'PENDING',
  },


  include:{


   user:{
    include:{
     rank:true,
    },
   },


   division:true,


  },


 });



 return res.json({

  requests,

 });


 }
);






app.post(
 '/api/divisions/requests/:id/decision',
 auth,
 permission('division.assign'),
 async(req,res)=>{


 const request =
 await db.divisionRequest.findUnique({

  where:{
   id:req.params.id,
  },

 });



 if(!request){

  return res.status(404).json({

   error:'Request not found',

  });

 }




 const accepted =
 Boolean(req.body.approved);




 await db.$transaction([


  db.divisionRequest.update({

   where:{
    id:request.id,
   },


   data:{


    status:
     accepted
     ? 'APPROVED'
     : 'REJECTED',


    decidedById:
     req.user.id,


    decidedAt:
     new Date(),


    decisionReason:
     req.body.reason,


   },


  }),



  ...(accepted
   ? [

    db.user.update({

     where:{
      id:request.userId,
     },


     data:{

      divisionId:
       request.divisionId,

     },


    }),

   ]

   : []

  ),


 ]);




 return res.json({

  ok:true,

 });


 }
);







/*
========================
 ANNOUNCEMENTS
========================
*/


app.get(
 '/api/announcements',
 auth,
 async(_req,res)=>{


 const announcements =
 await db.announcement.findMany({

  orderBy:{
   createdAt:'desc',
  },


  include:{

   author:{
    select:{
     name:true,
    },
   },

  },

 });



 return res.json({

  announcements,

 });


 }
);






app.post(
 '/api/announcements',
 auth,
 permission('announcement.create'),
 async(req,res)=>{


 const announcement =
 await db.announcement.create({

  data:{


   title:
    req.body.title,


   description:
    req.body.description,


   priority:
    req.body.priority ||
    'NORMAL',


   authorId:
    req.user.id,


  },


 });



 return res.status(201).json({

  announcement,

 });


 }
);







/*
========================
 LOGS
========================
*/


app.get(
 '/api/admin/logs',
 auth,
 permission('logs.view'),
 async(_req,res)=>{


 const logs =
 await db.auditLog.findMany({

  take:300,


  orderBy:{
   createdAt:'desc',
  },


  include:{


   actor:{
    select:{
     name:true,
     username:true,
    },
   },


  },

 });



 return res.json({

  logs,

 });


 }
);







/*
========================
 PLAYTIME SYSTEM
========================
*/


app.post(
 '/api/playtime/clock-in',
 auth,
 async(req,res)=>{


 let session =
 await db.playtimeSession.findFirst({

  where:{

   userId:
    req.user.id,


   logoutAt:
    null,


  },


 });



 if(!session){

  session =
  await db.playtimeSession.create({

   data:{


    userId:
     req.user.id,


    loginAt:
     new Date(),


   },

  });


 }




 await db.user.update({

  where:{
   id:req.user.id,
  },


  data:{

   online:true,

  },


 });



 return res.json({

  session,

 });


 }
);






app.post(
 '/api/playtime/clock-out',
 auth,
 async(req,res)=>{


 const session =
 await db.playtimeSession.findFirst({

  where:{


   userId:
    req.user.id,


   logoutAt:
    null,


  },

 });



 if(!session){

  return res.status(400).json({

   error:'No active session',

  });

 }



 const logout =
 new Date();



 const duration =
 Math.floor(

  (
   logout.getTime()
   -
   session.loginAt.getTime()

  )
  /
  60000

 );





 await db.playtimeSession.update({

  where:{
   id:session.id,
  },


  data:{


   logoutAt:
    logout,


   durationMinutes:
    duration,


  },

 });





 await db.user.update({

  where:{
   id:req.user.id,
  },


  data:{


   online:false,


   playtimeMinutes:{
    increment:
     duration,
   },


  },


 });




 return res.json({

  duration,

 });


 }
);







app.listen(
 PORT,
 ()=>{

 console.log(
  `Vanguard LSPD API running on ${PORT}`
 );

}
);
