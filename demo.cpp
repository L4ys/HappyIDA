// g++ -O0 demo.cpp -o demo && strip demo
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>   // for offsetof

// Inlay Hints
// rename and retype


struct CustomStruct{
    int    id;
    float  value;
    char   name[16];
};

void printStructure(CustomStruct* data){
    puts("In function printStructure");
    if(data == nullptr){
        puts("[Error] parameter data is null");
    }else{
        printf("id: %d\n", data->id);
        printf("value: %f\n", data->value);
        printf("name: %s\n", data->name);
    }
}

int main(void) {
    /* 
    *   [Demo]
    *   Inlay Hints
    *   lazyida:hx_copyname
    *   happyida:hx_pastename
    *   happyida:hx_edittype
    */
    CustomStruct* data = new CustomStruct();
    printStructure(data);
    /* 
    *   [Demo]
    *   happyida:hx_copytype
    *   happyida:hx_pastetype
    */
    void *raw_ptr = malloc(sizeof(CustomStruct));
    printf("id: %d\n",((CustomStruct*)raw_ptr)->id);
    free(raw_ptr);

    return 0;
}
