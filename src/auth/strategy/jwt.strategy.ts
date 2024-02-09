import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { PrismaService } from "src/prisma/prisma.service";

@Injectable()
export class JwtStrategy extends PassportStrategy(
    Strategy,
    'jwt',
    ){
    constructor(
        config: ConfigService, 
        private prisma: PrismaService
        ){
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.get('JWT_SECRET'),
        })
    }
    // on ovde importuje prizmu i trazi korisnika sve u ovoj funkciji, ja to ne bih radio
    // ako je ovo za desifrovanje jwt treba i da ostane tako
    // ja bih napraivo user.service i tu napravio funkciju koju bih zvao iz user.controller nakon desifrovanja
    async validate(payload: { sub: number; email: string; }){
        const user = await this.prisma.user.findUnique({
            where: {
                id: payload.sub,
            }
        })
        delete user.hash;
        return user;
        // sta god ovde returnovo bice mi dostupno u kontroleru gde sam iskoristio guard
        // mogu ga naci u @Req req: Request pod imenom req.user // zasto req.user a ne req.pusikurac -> boga pitaj
    
        
        // svi ovi komentari su napravljeni pre 2:12 u videu zato sto sad pravi custom dekoratore i mozda se nesto promeni
    }
}