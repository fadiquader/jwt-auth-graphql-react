import {Arg, Ctx, Field, Int, Mutation, ObjectType, Query, Resolver, UseMiddleware} from "type-graphql";
import {hash, compare} from "bcryptjs";
import {User} from "./entity/User";
import {sign, verify} from "jsonwebtoken";
import {MyContext} from "./MyContext";
import {createAccessToken, createRefreshToken} from "./auth";
import {isAuth} from "./isAuth";
import {sendRefreshToken} from "./sendRefreshToken";
import {getConnection} from "typeorm";

@ObjectType()
class LoginResponse {
  @Field()
  accessToken: string;
  @Field()
  user: User;
}
@Resolver()
export class UserResolver {
  @Query(() => String)
  @UseMiddleware(isAuth)
  bye(
    @Ctx() {payload}: MyContext
  ) {
    return `Your user id is: ${payload!.userId}`
  }
  @Query(() => [User])
  users() {
    return User.find();
  }
  @Query(() => User, { nullable: true })
  me(
    @Ctx() context: MyContext
  ) {
    const authorization = context.req.headers["authorization"];

    if (!authorization) {
      return null;
    }

    try {
      const token = authorization.split(" ")[1];
      const payload: any = verify(token, process.env.ACCESS_TOKEN_SECRET!);
      return User.findOne(payload.userId);
    } catch (err) {
      console.log(err);
      return null;
    }
  }
  @Mutation(() => Boolean)
  async logout(@Ctx() {res}: MyContext) {
    sendRefreshToken(res, "");
    return true;
  }
  @Mutation(() => Boolean)
  async revokeRefreshTokensForUser(
    @Arg('userId', () => Int) userId: number
  ) {
    await getConnection().getRepository(User).increment({id: userId}, "tokenVersion", 1)
    return true;
  }

  @Mutation(() => LoginResponse)
  async login(
    // @Arg('email', () => String) email: string
    @Arg('email') email: string,
    @Arg('password') password: string,
    @Ctx() ctx: MyContext
  ): Promise<LoginResponse> {
    const user = await User.findOne({
      where: {
        email
      }
    })
    if(!user) {
      throw new Error("Email doesn't exist")
    }
    const valid = await compare(password, user.password);
    if(!valid) {
      throw new Error("Bad password")
    }
    sendRefreshToken(ctx.res, createRefreshToken(user))
    return {
      accessToken: await createAccessToken(user),
      user
    };
  }
  @Mutation(() => Boolean)
  async register(
    @Arg('email') email: string,
    @Arg('password') password: string
  ) {
    const hashedPassword = await hash(password, 12)
    try {
      await User.insert({
        email,
        password: hashedPassword
      })
      return true;
    } catch (e) {
      return false;
    }
  }
}
