struct header_data
{
    char magic[4];
    unsigned __int16 version;
    unsigned __int16 flag;
    unsigned __int32 file_size;
    unsigned __int32 total_round;
};
struct round_data
{
    unsigned __int32 entity_id;
    unsigned __int16 attempts;
    unsigned __int16 length;
    unsigned __int64 secret_number;
};
struct gamedata
{
    struct header_data header_data;
    struct round_data *round_data_p;
    __int64 this_game_p;
    __int32 round;
};