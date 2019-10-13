import {Entity, PrimaryGeneratedColumn, Column, BaseEntity} from "typeorm";
import { ObjectType, Field, Int } from "type-graphql";

@ObjectType()
@Entity("users")
export class User extends BaseEntity {
    @Field(() => Int)
    @PrimaryGeneratedColumn()
    id: number;

    // @Column()
    // firstName: string;
    //
    // @Column()
    // lastName: string;
    @Field()
    @Column("text")
    email: string;

    @Column("text")
    password: string;

    @Column("int", { default: 0 })
    tokenVersion: number;

}
