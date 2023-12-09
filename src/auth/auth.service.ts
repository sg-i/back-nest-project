import { ForbiddenException, Injectable } from "@nestjs/common";
import {Bookmark, User} from '@prisma/client'
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
@Injectable({})
export class AuthService{
    constructor(
        private prisma: PrismaService, 
        private jwt: JwtService,
        private config: ConfigService
    ){}
    
    async signup(dto: AuthDto){
        //generate the passworh hash
        const hash = await argon.hash(dto.password);
        //save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash: hash
                },
                select:{
                    id: true,
                    email: true,
                    createdAt: true
                }
            })
            //return the saved user
            return user;    
        } catch (error) {
            if(error instanceof PrismaClientKnownRequestError){
                if(error.code==='P2002'){
                    throw new ForbiddenException('Credentials taken')
                }
                throw error;
            }
        }
        
    }

    async login(dto: AuthDto){

        // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            }
        })
        
        // if user doesn't exist throw exception
        if(!user) throw new ForbiddenException('Email incorrect')

        // compare password
        const pwMatches = await argon.verify(user.hash, dto.password);
        
        // if passwrd incorrect throw exception
        if(!pwMatches) throw new ForbiddenException('Password incorrect')
        
        // send back the user
        return this.signToken(user.id, user.email);
    }
    
    async signToken(userId: number, email: string): Promise<{access_token: string}>{
        const payload ={
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECREt');
        
        const token = await this.jwt.signAsync(payload,{
            expiresIn: '15m',
            secret: secret
        })

        return {
            access_token: token,
        }
    }
}
    