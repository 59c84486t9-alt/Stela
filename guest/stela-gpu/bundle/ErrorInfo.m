/* Command-buffer diagnostics and the shader-validation log collection. */
#include "Bundle.h"

@implementation StelaGPUEncoderInfo
@end

NSError *stela_command_error(const StelaFailure *failure, NSArray *encoders, BOOL submitted)
{
	NSString *description = [NSString stringWithUTF8String:failure->reason];
	NSMutableDictionary *information = [NSMutableDictionary dictionary];
	[information setObject:description forKey:NSLocalizedDescriptionKey];
	if (encoders) {
		BOOL execution_unknown = submitted || failure->status == StelaStatusDeviceLost
					 || failure->status == StelaStatusOutOfMemory;
		for (NSUInteger i = 0; i < encoders.count; i++) {
			StelaGPUEncoderInfo *encoder = encoders[i];
			/* Validation rejects the whole stream before submission. A driver
			 * failure may follow partially submitted sparse steps even when
			 * Commit returned no serial, so their execution stays unknown. */
			encoder.errorState = execution_unknown ? MTLCommandEncoderErrorStateUnknown
							      : MTLCommandEncoderErrorStatePending;
		}
		[information setObject:[encoders copy] forKey:MTLCommandBufferEncoderInfoErrorKey];
	}
	NSInteger code = failure->status == StelaStatusDeviceLost ? MTLCommandBufferErrorDeviceRemoved
			 : failure->status == StelaStatusOutOfMemory ? MTLCommandBufferErrorOutOfMemory
							   : MTLCommandBufferErrorInternal;
	return [NSError errorWithDomain:MTLCommandBufferErrorDomain code:code userInfo:information];
}

/* Function logs describe shader-validation diagnostics, rather than MTLLogState's
 * os_log messages. The compiler emits no validation records into that channel. */
@interface StelaGPUEmptyLogs : NSObject <MTLLogContainer>
@end

@implementation StelaGPUEmptyLogs

- (NSUInteger)countByEnumeratingWithState:(void *)state
				objects:(id __unsafe_unretained[])objects
				  count:(NSUInteger)count
{
	(void)state;
	(void)objects;
	(void)count;
	return 0;
}

@end

id stela_empty_logs(void)
{
	return [StelaGPUEmptyLogs new];
}
