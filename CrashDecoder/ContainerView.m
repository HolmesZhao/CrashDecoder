//
//  ContainerView.m
//  ContainerView
//
//  Created by xtrong@macbook on 2022/3/30.
//

#import "ContainerView.h"

@interface ContainerView ()

@property (weak) IBOutlet NSTextField *dSYMInput;
@property (weak) IBOutlet NSTextField *crashFileInput;
@property (weak) IBOutlet NSTextField *dSYMUUIDValue;
@property (weak) IBOutlet NSTextField *crashUUIDValue;
@property (weak) IBOutlet NSTextField *xcodeNameTF;

@property (weak) IBOutlet NSButton *symbolicateAynalyse;
@property (weak) IBOutlet NSButton *analyseBtn2;


@property (unsafe_unretained) IBOutlet NSTextView *outputView;


@property (nonatomic) NSTask *shellTask;
@property (nonatomic) NSString *xcodeName;
@property (nonatomic) NSString *symbolicatecrashPath;
@property (nonatomic) NSString *crashSymbolicatorPath;//CrashSymbolicator.py
@end

@implementation ContainerView


- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];
    
    // Drawing code here.
}


- (IBAction)analisyAllAction:(id)sender {
    //尝试symbolicate解析
    if (![self.crashUUIDValue.stringValue.uppercaseString isEqualToString:self.dSYMUUIDValue.stringValue.uppercaseString]) {
        self.outputView.string = @"UUID not matched";
    }else{
        if (!self.xcodeName) {
            [self getMyXcodeName];
        }
        //查找symbolicatecrash工具路径
        self.symbolicatecrashPath = [self runCommand:[NSString stringWithFormat:@"find /Applications/%@/Contents/SharedFrameworks -name symbolicatecrash -type f",self.xcodeName]];
        self.symbolicatecrashPath = [self.symbolicatecrashPath stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        //进行解析
        [self useSymbolicate2Analyse];
    }
}

- (IBAction)crashSymbolicatorPY_analyse:(id)sender {
    //尝试crashSymbolicator.py解析，支持iOS15之后json格式的crash日志
    if (![self.crashUUIDValue.stringValue.uppercaseString isEqualToString:self.dSYMUUIDValue.stringValue.uppercaseString]) {
        self.outputView.string = @"UUID not matched";
    }else{
        if (!self.xcodeName) {
            [self getMyXcodeName];
        }
        //查找CrashSymbolicator.py工具
        self.crashSymbolicatorPath = [self runCommand:[NSString stringWithFormat:@"find /Applications/%@/Contents/SharedFrameworks -name CrashSymbolicator.py -type f",self.xcodeName]];
        self.crashSymbolicatorPath = [self.crashSymbolicatorPath stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        //进行解析
        NSString *res = [self runCommand:[NSString stringWithFormat:@"python3 %@ -d %@ -p %@",self.crashSymbolicatorPath,self.dSYMInput.stringValue,self.crashFileInput.stringValue]];
        
        self.outputView.string = res;
    }
}

- (IBAction)exportSymbolicatedLog:(id)sender {
    NSSavePanel *panel = [NSSavePanel savePanel];
    panel.title = @"保存日志文件";
    panel.nameFieldStringValue = @"Result.crash";
    [panel setMessage:@"选择文件保存地址"];
    [panel setAllowsOtherFileTypes:YES];
    [panel setExtensionHidden:NO];
    [panel setCanCreateDirectories:YES];
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse result) {
        if (result) {
            NSString *path = [[panel URL] path];
            NSError *error;
            [self.outputView.string writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error];
        }
    }];
}

#pragma mark - 获取UUID
- (void)getMyXcodeName
{
    //先查找xcode名称，不同的xcode版本，APP名称不一致，例如可能是XCode-beta.app
    NSString *xcodeName = [self runCommand:@"ls /Applications/ | grep Xcode"];
    NSArray *xcodeNameArr = [xcodeName componentsSeparatedByString:@"\n"];
    NSString *userWriteName = [NSString stringWithFormat:@"%@.app", self.xcodeNameTF.stringValue ?: @"Xcode"];
    if ([xcodeNameArr containsObject:userWriteName]) {
        self.xcodeName = userWriteName;
    } else {
        self.xcodeName = [xcodeName stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    }
}
- (NSString *)getdSYM_UUID:(NSString *)dSYMPath
{
    NSString *commandString = [NSString stringWithFormat:@"dwarfdump --uuid \"%@\"",dSYMPath];
    NSString *uuidCMDInfo = [self runCommand:commandString];
    if (uuidCMDInfo) {
        NSString *uuid = [uuidCMDInfo substringWithRange:NSMakeRange(6, 36)];
        uuid = [uuid stringByReplacingOccurrencesOfString:@"-" withString:@""];
        return uuid;
    }else{
        return nil;
    }
}
- (NSString *)getCrash_UUID:(NSString *)crashFielPath
{
    NSString * firstLineStr = [self readFirstLine:crashFielPath];
    NSData *jsonData = [firstLineStr dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSDictionary *dictInfo = [NSJSONSerialization JSONObjectWithData:jsonData options:NSJSONReadingMutableContainers error:&error];
    if (dictInfo) {
        //第一行无uuid信息
        NSString *uuid = [dictInfo valueForKey:@"slice_uuid"];
        uuid = [uuid stringByReplacingOccurrencesOfString:@"-" withString:@""];
        return uuid?[uuid uppercaseString]:nil;
    }else{
        //通过binary images段获取
        NSString *wholeStr = [[NSString alloc] initWithContentsOfFile:crashFielPath];
        NSArray *wholeAry = [wholeStr componentsSeparatedByString:@"\n"];
        NSString *path = nil;
        for (int i=0;i<wholeAry.count;i++){
            NSString *tmpS = wholeAry[i];
            if ([tmpS containsString:@"Path:"]) {
                NSArray *pathComponets = [tmpS componentsSeparatedByString:@" "];
                path = [pathComponets lastObject];
                break;
            }
        }
        NSArray *ary = [wholeStr componentsSeparatedByString:@"Binary Images:"];
        if (ary.count == 2) {
            NSArray *binaryAry = [ary[1] componentsSeparatedByString:@"\n"];
            for (NSString *binaryStr in binaryAry) {
                if ([binaryStr containsString:path]) {
                    NSArray *resAry = [binaryStr componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
                    if (resAry.count == 3) {
                        NSString *uuid = resAry[1];
                        uuid = [uuid stringByReplacingOccurrencesOfString:@"-" withString:@""];
                        return uuid?[uuid uppercaseString]:nil;
                    }
                }
            }
        }
    }

    return nil;
}
- (NSString *)readFirstLine:(NSString *)crashFielPath
{
    FILE* file = fopen([crashFielPath cStringUsingEncoding:NSUTF8StringEncoding], "r");
    size_t length = 4096;
    char *cLine = fgetln(file,&length);
    char str[length+1];
    strncpy(str, cLine, length);
    str[length] = '\0';
    NSString *line = [NSString stringWithFormat:@"%s",str];
    return line;
}

- (NSString *)runCommand:(NSString *)commandToRun
{
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/sh"];
    
    NSArray *arguments = @[@"-c",
            [NSString stringWithFormat:@"%@", commandToRun]];

    [task setArguments:arguments];
    
    NSPipe *pipe = [NSPipe pipe];
    NSPipe *errPipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    [task setStandardError:errPipe];
    
    NSFileHandle *file = [pipe fileHandleForReading];
    NSFileHandle *errHandle = [errPipe fileHandleForReading];
    [task launch];
    
    NSData *data = [file readDataToEndOfFile];
    NSData *errData = [errHandle readDataToEndOfFile];
    NSString * errStr = [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding];
    
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return output;
}
- (void)useSymbolicate2Analyse
{
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = self.symbolicatecrashPath;
    NSArray *arguments = @[self.crashFileInput.stringValue, self.dSYMInput.stringValue];
    [task setArguments:arguments];
    NSDictionary *envi = @{@"DEVELOPER_DIR":[NSString stringWithFormat:@"/Applications/%@/Contents/Developer",self.xcodeName]};
    [task setEnvironment:envi];
    
    NSPipe *pipe = [NSPipe pipe];
    NSPipe *errPipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    [task setStandardError:errPipe];
    
    NSFileHandle *file = [pipe fileHandleForReading];
    NSFileHandle *errHandle = [errPipe fileHandleForReading];
    [task launch];
    
    NSData *data = [file readDataToEndOfFile];
    NSData *errData = [errHandle readDataToEndOfFile];
    NSString * errStr = [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding];
    
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!output.length && errStr.length) {
        if ([errStr containsString:@"No crash report"]) {
            errStr = [NSString stringWithFormat:@"试试CrashSymbolicator解析！\n%@",errStr];
            self.outputView.string = errStr;
        }else{
            self.outputView.string = errStr;
        }
    }else{
        self.outputView.string = output;
    }
}
- (NSString *)useCrashSymbolicator2Analyse
{
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = self.symbolicatecrashPath;
    NSArray *arguments = @[self.crashFileInput.stringValue, self.dSYMInput.stringValue];
    [task setArguments:arguments];
    NSDictionary *envi = @{@"DEVELOPER_DIR":[NSString stringWithFormat:@"/Applications/%@/Contents/Developer",self.xcodeName]};
    [task setEnvironment:envi];
    
    NSPipe *pipe = [NSPipe pipe];
    NSPipe *errPipe = [NSPipe pipe];
    [task setStandardOutput:pipe];
    [task setStandardError:errPipe];
    
    NSFileHandle *file = [pipe fileHandleForReading];
    NSFileHandle *errHandle = [errPipe fileHandleForReading];
    [task launch];
    
    NSData *data = [file readDataToEndOfFile];
    NSData *errData = [errHandle readDataToEndOfFile];
    NSString * errStr = [[NSString alloc] initWithData:errData encoding:NSUTF8StringEncoding];
    
    NSString *output = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return output;
}
#pragma mark - drag delegate
- (NSDragOperation)draggingEntered:(id <NSDraggingInfo>)sender{

    NSPasteboard *pboard = [sender draggingPasteboard];;
    NSDragOperation sourceDragMask = [sender draggingSourceOperationMask];
    
    if ( [[pboard types] containsObject:NSColorPboardType] ) {
        if (sourceDragMask & NSDragOperationGeneric) {
            return NSDragOperationGeneric;
        }
    }
    if ( [[pboard types] containsObject:NSFilenamesPboardType] ) {
        if (sourceDragMask & NSDragOperationLink) {
            return NSDragOperationLink;
        } else if (sourceDragMask & NSDragOperationCopy) {
            return NSDragOperationCopy;
        }
    }
    return NSDragOperationNone;
}

- (void)draggingExited:(id<NSDraggingInfo>)sender{
    NSLog(@"");
}

- (BOOL)performDragOperation:(id <NSDraggingInfo>)sender
{
    NSPasteboard *pboard = [sender draggingPasteboard];

    if([[pboard types] containsObject:NSFilenamesPboardType]){
        NSArray *files = [pboard propertyListForType:NSFilenamesPboardType];
        NSMutableArray *archiveFilePaths = [NSMutableArray arrayWithCapacity:1];
        BOOL hasValidFile = NO;
        for(NSString *filePath in files){
            if([filePath.pathExtension isEqualToString:@"crash"] ||
               [filePath.pathExtension isEqualToString:@"ips"]){
                [archiveFilePaths addObject:filePath];
                self.crashFileInput.stringValue = filePath;
                self.crashUUIDValue.stringValue = [self getCrash_UUID:filePath];
                hasValidFile = YES;
            }

            if([filePath.pathExtension isEqualToString:@"dSYM"]){
                [archiveFilePaths addObject:filePath];
                self.dSYMInput.stringValue = filePath;
                self.dSYMUUIDValue.stringValue = [self getdSYM_UUID:filePath];
                hasValidFile = YES;
            }
        }
        
        if(!hasValidFile){
            NSLog(@"没有包含dSYM或crash文件");
            return NO;
        }else{
            return YES;
        }
    }

    return NO;
}

@end
