#include <cstdlib>
struct Left {
    int health = 40;
    virtual int update(int amount) { health -= amount; return health; }
    virtual int state() { return health > 0 ? 1 : 2; }
};
struct Right {
    int counter = 0;
    virtual int update(int amount) { counter += amount; return counter; }
    virtual int state() { return counter; }
};
struct Player : Left, Right {
    int update(int amount) override { health -= amount; counter += amount; return health; }
    int state() override { return health > 0 ? 1 : 2; }
};
__attribute__((noinline)) int exercise(Left *left, Right *right, int amount) {
    int remaining = left->update(amount);
    int actions = right->update(amount);
    return remaining + actions + left->state() + right->state();
}
int main(int argc, char **) {
    for (int i = 0; i < 3; ++i) {
        auto *player = new Player;
        exercise(player, player, argc + i);
        delete player;
    }
    Left left;
    Right right;
    return exercise(&left, &right, 1) == 0;
}
