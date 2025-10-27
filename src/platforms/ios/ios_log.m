// iOS logging bridge - uses NSLog which appears in Console.app
#import <Foundation/Foundation.h>

void ios_log_message(const char *msg) {
    if (msg) {
        NSLog(@"%s", msg);
    }
}
