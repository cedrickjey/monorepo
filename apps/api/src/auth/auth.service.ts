import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(email: string, password: string) {
    const hashed = await bcrypt.hash(password, 10);
    const user = await this.prisma.user.create({
      data: { email, password: hashed },
    });
    return this.signToken(user.id, user.email, user.role);
  }

  async login(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid credentials');
    }
    return this.signToken(user.id, user.email, user.role);
  }

  private signToken(id: string, email: string, role: string) {
    const payload = { sub: id, email, role };
    const access_token = this.jwt.sign(payload, { expiresIn: '15m' });
    const refresh_token = this.jwt.sign(payload, { expiresIn: '7d' });
    return { access_token, refresh_token };
  }
}
