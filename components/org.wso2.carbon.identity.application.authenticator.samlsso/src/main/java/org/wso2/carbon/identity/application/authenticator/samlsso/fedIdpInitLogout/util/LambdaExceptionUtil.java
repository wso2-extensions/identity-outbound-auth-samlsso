/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.util;

import java.util.function.Consumer;

/**
 * A Utility which provides a way to throw checked exceptions from the lambda expressions.
 */
public class LambdaExceptionUtil {

    /**
     * Represents a {@code Consumer} interface which can throw exceptions.
     *
     * @param <T> the type of the input to the operation
     * @param <E> the type of Exception
     */
    @FunctionalInterface
    public interface ConsumerWithExceptions<T, E extends Exception> {
        void accept(T t) throws E;
    }

    /**
     * This method allows a Consumer which throws exceptions to be used in places which expects a Consumer.
     *
     * @param consumer instances of the {@code ConsumerWithExceptions} functional interface
     * @param <T>      the type of the input to the function
     * @param <E>      the type of Exception
     * @return an instance of the {@code Consumer}
     */
    public static <T, E extends Exception> Consumer<T> rethrowConsumer(ConsumerWithExceptions<T, E> consumer) {
        return t -> {
            try {
                consumer.accept(t);
            } catch (Exception exception) {
                throwAsUnchecked(exception);
            }
        };
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }
}

