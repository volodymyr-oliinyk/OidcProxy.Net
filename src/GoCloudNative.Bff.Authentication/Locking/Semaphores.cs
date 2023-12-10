using System.Collections.Concurrent;

namespace GoCloudNative.Bff.Authentication.Locking;

internal static class Semaphores
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Collection = new();

    public static SemaphoreSlim GetInstance(string key)
    {
        if (Collection.TryGetValue(key, out var value))
        {
            return value;
        }
        
        value = new SemaphoreSlim(1);
        if (!Collection.TryAdd(key, value))
        {
            throw new ApplicationException("Unable to obtain a lock.");
        }

        return value;
    }

    public static void RemoveInstance(string key)
    {
        Collection.Remove(key, out _);
    }
}