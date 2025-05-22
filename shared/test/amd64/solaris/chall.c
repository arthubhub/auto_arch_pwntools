#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <seccomp.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

#define MAX_SYSTEMS 4
#define MAX_PLANETS 8

struct system {
    char name[0x10];
    char* planets[MAX_PLANETS];
};

struct system* systems[MAX_SYSTEMS];
int max_systems = 0;

int get_num(void) {
    char choice[8];
    fgets(choice, sizeof(choice) - 1, stdin);
    return atoi(choice);
}

void create_system(void) {
    if (max_systems >= MAX_SYSTEMS)
        return;
    systems[max_systems] = calloc(1, sizeof(struct system));
    printf("Enter the solar system name\n>> ");
    read(0, systems[max_systems]->name, 0x10);
    systems[max_systems]->name[strlen(systems[max_systems]->name)] = 0x0;
    max_systems++;
    return;
}

void add_planet(int i, size_t size) {
    int j;
    if (i < 0 || i > max_systems)
        return;
    if (i == max_systems && systems[i] == NULL && i < MAX_SYSTEMS) {
        /** feature :
         *  if the system is not yet created, it creates it
         *  and also create the planet :) */
        systems[i] = calloc(1, sizeof(struct system));
        systems[i]->planets[0] = malloc(size);
        printf("Enter the planet name\n>> ");
        fgets(systems[i]->planets[0], size - 1, stdin);
        printf("Enter the solar system name\n>> ");
        int size = read(0, systems[i]->name, 0x10);
        systems[i]->name[size] = 0x0;
        max_systems++;
    }
    else {
        for (j = 0 ; j < MAX_PLANETS ; j++)
            if (systems[i]->planets[j] == NULL)
                break;
        if (j == MAX_PLANETS)
            return;
        systems[i]->planets[j] = malloc(size);
        printf("Enter the planet name\n>> ");
        fgets(systems[i]->planets[j], size - 1, stdin);
    }
}

void delete_planet(int i, int j) {
    if (i < 0 || i >= max_systems || systems[i] == NULL)
        return;
    if (j < 0 || j >= MAX_PLANETS || systems[i]->planets[j] == NULL)
        return;
    free(systems[i]->planets[j]);
    systems[i]->planets[j] = NULL;
}

void edit_planet(int i, int j) {
    if (i < 0 || i >= max_systems || systems[i] == NULL)
        return;
    if (j < 0 || j >= MAX_PLANETS || systems[i]->planets[j] == NULL)
        return;
    printf("Enter the new planet name\n>> ");
    fgets(systems[i]->planets[j], strlen(systems[i]->planets[j]) + 1, stdin);
}

void show_planet(int i, int j) {
    if (i < 0 || i >= max_systems || systems[i] == NULL)
        return;
    if (j < 0 || j >= MAX_PLANETS || systems[i]->planets[j] == NULL)
        return;
    write(1, systems[i]->planets[j], strlen(systems[i]->planets[j]));
    puts("");
}

void menu(void) {
    fflush(stdout);
    puts("                                      ⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀  ");
    puts("                               ⠀⠀⠀⢠⠄⠀⡐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠳⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts("  =========================    ⠀⠀⠀⡈⣀⡴⢧⣀⠀⠀⣀⣠⠤⠤⠤⠤⣄⣀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀");
    puts(" | 1. create solar system |    ⠀⠀⠀⠀⠀⠘⠏⢀⡴⠊⠁⠀⠄⠀⠀⠀⠀⠈⠙⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀");
    puts(" | 2. create planet       |  ⠀⠀⠀⠀⠀⠀⠀⠀⣰⠋⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠘⢶⣶⣒⡶⠦⣠⣀⠀");
    puts(" | 3. delete planet       |  ⠀⠀⠀⠀⠀⠀⢀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠈⣟⠲⡎⠙⢦⠈⢧");
    puts(" | 4. edit planet         |  ⠀⠀⠀⣠⢴⡾⢟⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡰⢃⡠⠋⣠⠋");
    puts(" | 5. show planet         |  ⠐⠀⠞⣱⠋⢰⠁⢿⠀⠀⠀⠀⠄⢂⠀⠀⠀⠀⠀⣀⣠⠠⢖⣋⡥⢖⣩⠔⠊⠀⠀");
    puts(" | 6. leave solaris       |   ⠈⠠⡀⠹⢤⣈⣙⠚⠶⠤⠤⠤⠴⠶⣒⣒⣚⣨⠭⢵⣒⣩⠬⢖⠏⠁⢀⣀⠀⠀");
    puts("  =========================⠀     ⠀⠈⠓⠒⠦⠍⠭⠭⣭⠭⠭⠭⠭⡿⡓⠒⠛⠉⠉⣠⠇⠀⠀⠘⠞ ");
    puts("                       ⠀⠀ ⠀⠀     ⠀⠀⠀⠀⠈⠓⢤⣀⠀⠁⠀⠀⠀⠀ ⣀⡤⠞⠁⠀⣰⣆⠀⠀⠀⠀ ");
    puts("                           ⠀     ⠀⠀⠿⠀⠀⠀⠀⠀⠉⠉⠙⠒⠒⠚⠉⠁⠀⠀  ⠁⢣⡎⠁⠀⠀");
    puts("");
}

void init_seccomp(void) {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2, 
                          SCMP_A0(SCMP_CMP_EQ, 1),
                          SCMP_A1(SCMP_CMP_EQ, 2));
    seccomp_load(ctx);
}

int main(void) {
    int i, j;
    int choice;
    size_t size;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    init_seccomp();

    while (1) {
        menu();
        printf("Enter your choice\n> ");
        choice = get_num();
        switch (choice) {
            case 1:
                puts("Creating solar system...");
                create_system();
                break;
            case 2:
                puts("Creating planet...");
                printf("Enter the solar system number\n>> ");
                i = get_num();
                printf("Choose the planet size\n>> ");
                size = (size_t)get_num();
                add_planet(i, size);
                break;
            case 3:
                puts("Deleting planet...");
                printf("Enter the solar system number\n>> ");
                i = get_num();
                printf("Enter the planet number\n>> ");
                j = get_num();
                delete_planet(i, j);
                break;
            case 4:
                puts("Editing planet...");
                printf("Enter the solar system number\n>> ");
                i = get_num();
                printf("Enter the planet number\n>> ");
                j = get_num();
                edit_planet(i, j);
                break;
            case 5:
                printf("Enter the solar system number\n>> ");
                i = get_num();
                printf("Enter the planet number\n>> ");
                j = get_num();
                show_planet(i, j);
                break;
            case 6:
                puts("Leaving solaris...");
                goto end;
                break;
            default:
                puts("Invalid choice!");
                break;
        }
    }
end:
    return 0;
}
