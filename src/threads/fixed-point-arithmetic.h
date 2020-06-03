# ifndef _FIXED_POINT_ARITHMETIC_ 
# define _FIXED_POINT_ARITHMETIC_


typedef int32_t fixed_point;

#define FIXED_PART_MASK 0x3fff;
#define INTEGER_PART_MASK (0x1ffff << 14);
#define SIGN_BIT_MASK (1<<31)

#define F (1<<14)
#define convert_to_fix(X) X*F
#define convert_to_int(X) X/F
#define convert_to_nearest(X) X >= 0 ? convert_to_int((X + F/2)) : convert_to_int((X-F/2))

#define add_fix_int(X,Y) X + convert_to_fix(Y)
#define sub_fix_int(X,Y) X - convert_to_fix(Y)
#define mult_fix_int(X,Y) X * Y 
#define div_fix_int(X,Y)  X / Y

#define mult_fix2(X,Y) (((int64_t)X) * Y ) / F
#define div_fix2(X,Y)  (((int64_t)X) * F ) / Y

#endif
