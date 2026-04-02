// Experiment 8: Objective-C ARC
// Build with: -fobjc-arc -framework Foundation
// Expected: _objc_retain, _objc_release in imports
#import <Foundation/Foundation.h>

@interface Foo : NSObject
@property (nonatomic, strong) NSString *name;
@end

@implementation Foo
- (instancetype)initWithName:(NSString *)name {
    self = [super init];
    if (self) { _name = name; }
    return self;
}
- (void)greet {
    NSLog(@"Hello, %@", _name);
}
@end

int main(int argc, const char **argv) {
    @autoreleasepool {
        Foo *foo = [[Foo alloc] initWithName:@"World"];
        [foo greet];
    }
    return 0;
}
